package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAgentMetricsAndDueJobs(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "am.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sid, _ := st.CreateChatSession("")

	if err := st.MergeAgentMetrics(sid, 2, 5, 1, 1200, 100, 40, 140); err != nil {
		t.Fatal(err)
	}
	if err := st.MergeAgentMetrics(sid, 1, 3, 0, 800, 50, 10, 60); err != nil {
		t.Fatal(err)
	}
	m, err := st.GetAgentMetrics(sid)
	if err != nil || m.Runs != 2 || m.Rounds != 3 || m.ToolCalls != 8 || m.ToolErrors != 1 || m.TotalTokens != 200 || m.LastDurationMs != 800 {
		t.Fatalf("metrics = %+v err=%v", m, err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	immediate, _ := st.CreateAgentJob(sid, "立即任务", "")
	scheduled, _ := st.CreateAgentJob(sid, "定时任务", future)

	due, err := st.ListDueAgentJobs(now)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int64]bool{}
	for _, j := range due {
		seen[j.ID] = true
	}
	if !seen[immediate] || seen[scheduled] {
		t.Fatalf("due jobs = %+v (immediate=%d scheduled=%d)", due, immediate, scheduled)
	}
	if err := st.UpdateAgentJobAttempts(immediate, 1); err != nil {
		t.Fatal(err)
	}
	if j, _ := st.GetAgentJob(immediate); j.Attempts != 1 {
		t.Fatalf("attempts = %d", j.Attempts)
	}
	runs, err := st.GetAgentRuns(sid, 10)
	if err != nil || len(runs) != 2 || runs[0].TotalTokens != 60 {
		t.Fatalf("runs = %+v err=%v", runs, err)
	}

	_ = st.UpdateAgentJobStatus(scheduled, "awaiting", "", "")
	if j, ok, err := st.LatestAwaitingAgentJob(sid); err != nil || !ok || j.ID != scheduled {
		t.Fatalf("awaiting = %+v ok=%v err=%v", j, ok, err)
	}
	if err := st.MarkAgentJobResumed(scheduled); err != nil {
		t.Fatal(err)
	}
	if j, _ := st.GetAgentJob(scheduled); j.Resumed != 1 {
		t.Fatalf("resumed = %d", j.Resumed)
	}
}

func TestAgentJobCancelAndRetry(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "jc.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sid, _ := st.CreateChatSession("")
	id, _ := st.CreateAgentJob(sid, "任务", "")
	if ok, _ := st.CancelAgentJob(id); !ok {
		t.Fatal("cancel queued job failed")
	}
	if j, _ := st.GetAgentJob(id); j.Status != "canceled" {
		t.Fatalf("status = %s", j.Status)
	}
	if ok, _ := st.RetryAgentJob(id); !ok {
		t.Fatal("retry canceled job failed")
	}
	j, _ := st.GetAgentJob(id)
	if j.Status != "queued" || j.Resumed != 1 || j.Error != "" {
		t.Fatalf("retried job = %+v", j)
	}
	_ = st.UpdateAgentJobStatus(id, "done", "ok", "")
	if ok, _ := st.RetryAgentJob(id); ok {
		t.Fatal("done job should not be retryable")
	}
}
