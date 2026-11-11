package web

// Background agent jobs: a queued prompt runs the same tool loop as an
// interactive turn, but detached from the console connection. Progress is
// persisted into the chat session, so the operator can open the session later
// and read the transcript even if the browser was closed.
//
// Jobs support multiple workers, one retry with a resume prompt, and scheduled
// run_at times (used for follow-ups such as "summarise 24h after sending").

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"phishsim/internal/features/llm"
)

// agentJobTimeout bounds one background run. The worker is single-threaded, so
// a wedged provider cannot starve the queue forever.
const agentJobTimeout = 30 * time.Minute

func agentWorkerCount() int {
	n, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("PHISH_AGENT_WORKERS")))
	if n <= 0 {
		n = 2
	}
	if n > 8 {
		n = 8
	}
	return n
}

func agentJobRetries() int {
	n, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("PHISH_AGENT_JOB_RETRIES")))
	if n < 0 {
		n = 0
	}
	if n > 5 {
		n = 5
	}
	return n
}

// agentJobPendingTTL matches the pending-action confirmation window.
const agentJobPendingTTL = 15 * time.Minute

// StartAgentWorker launches the queue consumers and the scheduler ticker once.
func (s *Server) StartAgentWorker() {
	s.jobStart.Do(func() {
		s.jobCh = make(chan int64, 64)
		if s.jobQueued == nil {
			s.jobQueued = map[int64]bool{}
		}
		for i := 0; i < agentWorkerCount(); i++ {
			go func() {
				for id := range s.jobCh {
					s.clearQueuedJob(id)
					s.runAgentJob(id)
				}
			}()
		}
		if s.Store == nil {
			return
		}
		// A run interrupted by a restart is safe to resume from its transcript,
		// but it must not re-insert the original prompt.
		if jobs, err := s.Store.ListActiveAgentJobs(); err == nil {
			for _, j := range jobs {
				if j.Status == "running" {
					_ = s.Store.MarkAgentJobResumed(j.ID)
					_ = s.Store.UpdateAgentJobStatus(j.ID, "queued", "", "")
				}
			}
		}
		// Pending confirmations live in memory and were lost with the process.
		if awaiting, err := s.Store.ListAwaitingAgentJobs(); err == nil {
			for _, j := range awaiting {
				_ = s.Store.UpdateAgentJobStatus(j.ID, "error", "", "确认已失效（进程重启），请重新发起任务")
				s.recordAgentNote(j.SessionID, "⚠️ 后台任务停止：等待确认期间进程重启，确认已失效，请重新发起同名任务。")
			}
		}
		s.enqueueDueJobs()
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				s.expireStaleAwaitingJobs()
				s.enqueueDueJobs()
			}
		}()
	})
}

// expireStaleAwaitingJobs stops jobs whose confirmation window has elapsed.
func (s *Server) expireStaleAwaitingJobs() {
	jobs, err := s.Store.ListAwaitingAgentJobs()
	if err != nil {
		return
	}
	for _, j := range jobs {
		t, perr := time.Parse(time.RFC3339Nano, j.UpdatedAt)
		if perr != nil || time.Since(t) < agentJobPendingTTL {
			continue
		}
		_ = s.Store.UpdateAgentJobStatus(j.ID, "error", "", "确认已过期（15 分钟），任务已停止")
		s.recordAgentNote(j.SessionID, "⚠️ 后台任务停止：等待确认超过 15 分钟，任务已结束。")
	}
}

func (s *Server) enqueueDueJobs() {
	if s.Store == nil {
		return
	}
	jobs, err := s.Store.ListDueAgentJobs(time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return
	}
	for _, j := range jobs {
		s.enqueueAgentJob(j.ID)
	}
}

func (s *Server) enqueueAgentJob(id int64) {
	if s.jobCh == nil {
		return
	}
	s.jobMu.Lock()
	if s.jobQueued == nil {
		s.jobQueued = map[int64]bool{}
	}
	if s.jobQueued[id] {
		s.jobMu.Unlock()
		return
	}
	s.jobQueued[id] = true
	s.jobMu.Unlock()
	select {
	case s.jobCh <- id:
	default:
		go func() { s.jobCh <- id }()
	}
}

func (s *Server) clearQueuedJob(id int64) {
	s.jobMu.Lock()
	delete(s.jobQueued, id)
	s.jobMu.Unlock()
}

// startBackgroundTask queues a self-contained prompt. delayMinutes > 0 makes
// it a scheduled follow-up picked up by the worker ticker.
func (s *Server) startBackgroundTask(sessionID int64, prompt string, delayMinutes int) (int64, error) {
	if s.Store == nil {
		return 0, fmt.Errorf("存储未就绪")
	}
	if sessionID <= 0 {
		return 0, fmt.Errorf("需要会话（session_id）")
	}
	if _, err := s.Store.GetChatSession(sessionID); err != nil {
		return 0, fmt.Errorf("会话不存在")
	}
	active, _ := s.Store.ListActiveAgentJobs()
	for _, j := range active {
		if j.SessionID == sessionID {
			return 0, fmt.Errorf("该会话已有后台任务在排队或执行，请等它结束")
		}
	}
	runAt := ""
	if delayMinutes > 0 {
		runAt = time.Now().Add(time.Duration(delayMinutes) * time.Minute).UTC().Format(time.RFC3339Nano)
	}
	id, err := s.Store.CreateAgentJob(sessionID, prompt, runAt)
	if err != nil {
		return 0, err
	}
	s.StartAgentWorker()
	if runAt == "" {
		s.enqueueAgentJob(id)
	}
	return id, nil
}

// resumeAwaitingJob continues a background job after the operator resolves the
// confirmation that parked it. The job resumes from the transcript; the
// original prompt is not inserted again.
func (s *Server) resumeAwaitingJob(sessionID int64) {
	if s.Store == nil || sessionID <= 0 {
		return
	}
	job, ok, err := s.Store.LatestAwaitingAgentJob(sessionID)
	if err != nil || !ok {
		return
	}
	_ = s.Store.MarkAgentJobResumed(job.ID)
	if err := s.Store.UpdateAgentJobStatus(job.ID, "queued", "", ""); err != nil {
		return
	}
	s.recordAgentNote(sessionID, "▶ 已确认，后台任务自动继续")
	s.StartAgentWorker()
	s.enqueueAgentJob(job.ID)
}

// runAgentJob executes one queued job and records the result.
func (s *Server) runAgentJob(id int64) {
	job, err := s.Store.GetAgentJob(id)
	if err != nil || (job.Status != "queued" && job.Status != "running") {
		return
	}
	_ = s.Store.UpdateAgentJobStatus(id, "running", "", "")
	fail := func(msg string) {
		_ = s.Store.UpdateAgentJobStatus(id, "error", "", truncateRunes(msg, 2000))
		s.recordAgentNote(job.SessionID, "⚠️ 后台任务失败："+msg)
		s.notifyAlert("agent_job_failed", map[string]any{"job": id, "session": job.SessionID, "error": msg})
	}
	text := strings.TrimSpace(job.Prompt)
	if text == "" {
		fail("任务内容为空")
		return
	}
	sess, err := s.Store.GetChatSession(job.SessionID)
	if err != nil {
		fail("会话不存在")
		return
	}
	cli := s.getLLM()
	if cli == nil || !cli.Available() {
		fail("LLM 未配置，无法执行后台任务")
		return
	}

	var history []llm.Message
	if job.Attempts == 0 && job.Resumed == 0 {
		s.persistTurn(job.SessionID, llm.Message{Role: "user", Content: text}, text)
		if strings.TrimSpace(sess.Title) == "" {
			title := strings.Join(strings.Fields(text), " ")
			_ = s.Store.RenameChatSession(job.SessionID, truncateRunes(title, 30))
		}
		history = s.loadAgentHistory(job.SessionID)
	} else {
		// Retry/resume: the transcript already holds the original prompt.
		history = s.loadAgentHistory(job.SessionID)
		history = append(history, llm.Message{Role: "user", Content: "[系统] 操作员已处理待确认事项，后台任务从中断处继续；不要重复已完成的操作。"})
	}

	ctx, cancel := context.WithTimeout(context.Background(), agentJobTimeout)
	defer cancel()
	s.jobCancelMu.Lock()
	if s.jobCancels == nil {
		s.jobCancels = map[int64]context.CancelFunc{}
	}
	s.jobCancels[id] = cancel
	s.jobCancelMu.Unlock()
	defer func() {
		s.jobCancelMu.Lock()
		delete(s.jobCancels, id)
		s.jobCancelMu.Unlock()
	}()
	out, usage, err := s.runAgent(ctx, cli, "", job.SessionID, history, func(any) error { return nil })
	if err != nil {
		if ctx.Err() == context.Canceled {
			_ = s.Store.UpdateAgentJobStatus(id, "canceled", "", "任务已由操作员取消")
			s.recordAgentNote(job.SessionID, "⏹ 后台任务已取消")
			return
		}
		if job.Attempts < agentJobRetries() {
			next := job.Attempts + 1
			_ = s.Store.UpdateAgentJobAttempts(id, next)
			_ = s.Store.UpdateAgentJobStatus(id, "queued", "", "")
			s.recordAgentNote(job.SessionID, fmt.Sprintf("↻ 后台任务中断，%d 秒后自动重试（第 %d 次）", 10*next, next))
			time.AfterFunc(time.Duration(10*next)*time.Second, func() { s.enqueueAgentJob(id) })
			return
		}
		fail(err.Error())
		return
	}
	s.Store.RecordLLMUsage(cli.Model, usage.PromptTokens, usage.CompletionTokens, usage.TotalTokens)
	// A background job has no SSE channel: if the model parked a confirmation,
	// mark the job honestly instead of reporting a false "done".
	if len(s.pendingActionsFor(job.SessionID)) > 0 || len(s.pendingConfirmsFor(job.SessionID)) > 0 {
		s.recordAgentNote(job.SessionID, "⏸ 后台任务等待操作员确认：请打开本会话处理待确认操作，确认后重新发一条「继续」即可从断点续跑。")
		_ = s.Store.UpdateAgentJobStatus(id, "awaiting", truncateRunes(out, 2000), "")
		return
	}
	_ = s.Store.UpdateAgentJobStatus(id, "done", truncateRunes(out, 2000), "")
}

// adminAgentJobs lists jobs or queues a new one.
func (s *Server) adminAgentJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jobs, err := s.Store.ListAgentJobs(50)
		if err != nil {
			s.writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		s.writeJSON(w, 200, map[string]any{"jobs": jobs})
	case http.MethodPost:
		var req struct {
			SessionID    int64  `json:"session_id"`
			Message      string `json:"message"`
			DelayMinutes int    `json:"delay_minutes"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		text := strings.TrimSpace(req.Message)
		if text == "" {
			s.writeJSON(w, 400, map[string]any{"error": "message required"})
			return
		}
		id, err := s.startBackgroundTask(req.SessionID, text, req.DelayMinutes)
		if err != nil {
			s.writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		s.log().Info("agent background job queued", "job", id, "session", req.SessionID,
			"delay_minutes", req.DelayMinutes, "ip", s.remoteIP(r))
		s.writeJSON(w, 200, map[string]any{"id": id, "status": "queued"})
	default:
		s.writeJSON(w, 405, map[string]any{"error": "GET or POST"})
	}
}

// agentJobView is the tool-facing confirmation after queueing.
func agentJobView(id int64) string {
	b, _ := json.Marshal(map[string]any{"job_id": id, "status": "queued"})
	return string(b)
}

// adminAgentJobAction cancels or retries one background job.
func (s *Server) adminAgentJobAction(w http.ResponseWriter, r *http.Request, id int64, action string) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	job, _ := s.Store.GetAgentJob(id)
	switch action {
	case "cancel":
		s.jobCancelMu.Lock()
		cancel := s.jobCancels[id]
		s.jobCancelMu.Unlock()
		ok, err := s.Store.CancelAgentJob(id)
		if err != nil {
			s.writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		if !ok {
			s.writeJSON(w, 400, map[string]any{"error": "该任务当前状态不能取消"})
			return
		}
		if cancel != nil {
			cancel()
		}
		if job.SessionID > 0 {
			s.recordAgentNote(job.SessionID, "⏹ 后台任务已取消")
		}
		s.writeJSON(w, 200, map[string]any{"canceled": id})
	case "retry":
		ok, err := s.Store.RetryAgentJob(id)
		if err != nil {
			s.writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		if !ok {
			s.writeJSON(w, 400, map[string]any{"error": "只有失败或已取消的任务可以重试"})
			return
		}
		if job.SessionID > 0 {
			s.recordAgentNote(job.SessionID, "↻ 后台任务已重新排队，将从断点继续")
		}
		s.StartAgentWorker()
		s.enqueueAgentJob(id)
		s.writeJSON(w, 200, map[string]any{"retried": id})
	default:
		s.writeJSON(w, 404, map[string]any{"error": "unknown action"})
	}
}
