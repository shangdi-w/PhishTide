package web

// Read-only sub-agents. The main loop can fan independent verification work out
// to a small number of child loops that only see read-only tools and cannot
// recurse. They never touch a write tool, never send, and never persist chat
// turns; the parent gets back a short conclusion plus usage.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"phishsim/internal/core/store"
	"phishsim/internal/features/llm"
)

const (
	// maxSubagents bounds one dispatch_subagents call.
	maxSubagents = 4
	// maxSubagentRounds bounds each child loop.
	maxSubagentRounds = 6
	// maxSubagentReport caps the conclusion handed back to the parent.
	maxSubagentReport = 2400
	// maxSubagentResult caps a single tool result inside a child loop.
	maxSubagentResult = 6000
	// subagentTimeout bounds one child loop end to end.
	subagentTimeout = 3 * time.Minute
)

// subagentTask is one instruction in a dispatch_subagents call.
type subagentTask struct {
	Title       string `json:"title,omitempty"`
	Instruction string `json:"instruction"`
}

// subagentReport is one child loop's result.
type subagentReport struct {
	Title       string    `json:"title,omitempty"`
	Instruction string    `json:"instruction"`
	Result      string    `json:"result,omitempty"`
	Error       string    `json:"error,omitempty"`
	Rounds      int       `json:"rounds"`
	ToolCalls   int       `json:"tool_calls"`
	Usage       llm.Usage `json:"usage,omitempty"`
}

// agentRuntime carries the model and client from the parent loop into tool
// execution, so dispatch_subagents can give its children the same provider.
type agentRuntime struct {
	client *llm.Client
	model  string
}

type agentRuntimeKey struct{}

func withAgentRuntime(ctx context.Context, cli *llm.Client, model string) context.Context {
	rt := agentRuntime{client: cli, model: model}
	if prev, ok := ctx.Value(agentRuntimeKey{}).(agentRuntime); ok {
		if rt.client == nil {
			rt.client = prev.client
		}
		if rt.model == "" {
			rt.model = prev.model
		}
	}
	return context.WithValue(ctx, agentRuntimeKey{}, rt)
}

func agentRuntimeFrom(ctx context.Context) (agentRuntime, bool) {
	rt, ok := ctx.Value(agentRuntimeKey{}).(agentRuntime)
	return rt, ok && rt.client != nil
}

const subagentPrompt = `你是主代理派出的只读子代理，只负责核验一个独立问题。
规则：
1. 只能用只读工具（列举、读取、自检、干跑、报告）。任何写库、创建、修改、发送的请求一律拒绝并说明原因。
2. 遵循假设驱动：先立假设，再取证据，最后给判定（成立/不成立/无法判定）。
3. 结论必须带证据：对象 id/名称、关键字段或错误文本；不要空泛复述。
4. 不扩散范围：只回答分配给你的问题，发现范围外的线索只记录一句「另见」，不要继续追查。
5. 最多 6 轮工具调用；足够下结论就停止调用并输出结论。
最终回答格式：
结论：<一句话>
证据：
- <证据 1>
- <证据 2>
建议：<主代理下一步该做什么，没有就写「无」>`

// dispatchSubagents runs the child loops concurrently and returns their reports
// in the same order as the tasks.
func (s *Server) dispatchSubagents(ctx context.Context, tasks []subagentTask) []subagentReport {
	if len(tasks) > maxSubagents {
		tasks = tasks[:maxSubagents]
	}
	out := make([]subagentReport, len(tasks))
	var wg sync.WaitGroup
	for i := range tasks {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out[i] = s.runSubAgent(ctx, tasks[i])
		}(i)
	}
	wg.Wait()
	return out
}

// runSubAgent runs one read-only child loop. Errors become report.Error rather
// than propagating, so one failed child never loses its siblings' work.
func (s *Server) runSubAgent(ctx context.Context, task subagentTask) subagentReport {
	rep := subagentReport{Title: task.Title, Instruction: task.Instruction}
	rt, ok := agentRuntimeFrom(ctx)
	if !ok {
		rep.Error = "缺少模型运行上下文，无法派遣子代理"
		return rep
	}
	cctx, cancel := context.WithTimeout(ctx, subagentTimeout)
	defer cancel()

	msgs := []llm.Message{
		{Role: "system", Content: subagentPrompt},
		{Role: "user", Content: task.Instruction},
	}
	tools := readOnlyAgentTools()
	for round := 0; round < maxSubagentRounds; round++ {
		rep.Rounds = round + 1
		res, err := rt.client.ChatWithTools(cctx, rt.model, msgs, tools, nil)
		if err != nil {
			rep.Error = truncateRunes(err.Error(), 400)
			return rep
		}
		rep.Usage.PromptTokens += res.Usage.PromptTokens
		rep.Usage.CompletionTokens += res.Usage.CompletionTokens
		rep.Usage.TotalTokens += res.Usage.TotalTokens

		msgs = append(msgs, llm.Message{Role: "assistant", Content: res.Content, ToolCalls: res.ToolCalls})
		if len(res.ToolCalls) == 0 {
			rep.Result = truncateRunes(strings.TrimSpace(res.Content), maxSubagentReport)
			if rep.Result == "" {
				rep.Error = "子代理未给出结论"
			}
			return rep
		}
		for _, call := range res.ToolCalls {
			rep.ToolCalls++
			raw := s.runSubAgentTool(cctx, call)
			msgs = append(msgs, llm.Message{
				Role: "tool", ToolCallID: call.ID, Name: call.Function.Name,
				Content: capSubagentResult(raw),
			})
		}
	}
	rep.Error = fmt.Sprintf("超过 %d 轮工具调用仍未给出结论", maxSubagentRounds)
	return rep
}

// runSubAgentTool executes one read-only tool call, refusing anything outside
// the read-only subset (including recursion back into dispatch_subagents).
func (s *Server) runSubAgentTool(ctx context.Context, call llm.ToolCall) string {
	spec, known := agentToolMeta(call.Function.Name)
	if !known || !spec.ReadOnly || call.Function.Name == "dispatch_subagents" {
		b, _ := json.Marshal(map[string]any{
			"error": "子代理只能调用只读工具，已拒绝: " + call.Function.Name,
		})
		return string(b)
	}
	// sessionID 0 keeps sub-agents out of the operator's chat session state.
	raw, _, _ := s.executeTool(ctx, 0, call, func(any) error { return nil })
	return raw
}

// capSubagentResult keeps one child tool result small enough that several
// rounds still fit in the context window.
func capSubagentResult(result string) string {
	if utf8.RuneCountInString(result) <= maxSubagentResult {
		return result
	}
	b, _ := json.Marshal(map[string]any{
		"truncated": true,
		"note":      "子代理工具结果过长，已截断",
		"preview":   truncateRunes(result, maxSubagentResult),
	})
	return string(b)
}

// ---------------------------------------------------------------------------
// Task ledger helpers

// todoSummary renders a checklist as one short line for tool notes.
func todoSummary(todos []store.AgentTodo) string {
	if len(todos) == 0 {
		return "（空）"
	}
	done := 0
	parts := make([]string, 0, len(todos))
	for _, t := range todos {
		if t.Status == "done" {
			done++
		}
		parts = append(parts, "["+t.Status+"] "+truncateRunes(t.Text, 60))
	}
	return fmt.Sprintf("%d/%d 完成；%s", done, len(todos), strings.Join(parts, "；"))
}

// todoPromptBlock renders the current checklist for the system prompt so the
// model can recover its plan after context trimming.
func (s *Server) todoPromptBlock(sessionID int64) string {
	if s.Store == nil || sessionID <= 0 {
		return ""
	}
	todos, err := s.Store.ListAgentTodos(sessionID)
	if err != nil || len(todos) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[当前任务清单（会话级，跨轮次保留；状态以这里为准）]\n")
	for _, t := range todos {
		mark := " "
		switch t.Status {
		case "done":
			mark = "x"
		case "in_progress":
			mark = ">"
		}
		b.WriteString(fmt.Sprintf("- [%s] %s\n", mark, truncateRunes(t.Text, 200)))
	}
	b.WriteString("规则：多步骤任务先 todo_write 建清单；每完成一项立即更新状态；全部完成后把清单标成 done，不要留 in_progress。\n")
	return b.String()
}
