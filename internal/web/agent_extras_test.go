package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"phishsim/internal/core/store"
	"phishsim/internal/features/llm"
)

func TestTodoWritePersistsAndFeedsPrompt(t *testing.T) {
	s := newAgentServer(t)
	sid, _ := s.Store.CreateChatSession("")

	out, ok, note := execTool(t, s, sid, "todo_write", map[string]any{
		"items": []map[string]any{
			{"text": "建邮件模板", "status": "in_progress"},
			{"text": "发活动", "status": "pending"},
		},
	})
	if !ok || !strings.Contains(note, "0/2") {
		t.Fatalf("todo_write = %+v, ok=%v, note=%q", out, ok, note)
	}
	todos, err := s.Store.ListAgentTodos(sid)
	if err != nil || len(todos) != 2 || todos[0].Text != "建邮件模板" || todos[0].Status != "in_progress" {
		t.Fatalf("todos = %+v, err=%v", todos, err)
	}

	block := s.todoPromptBlock(sid)
	if !strings.Contains(block, "建邮件模板") || !strings.Contains(block, "[>]") {
		t.Fatalf("prompt block = %q", block)
	}

	out, ok, _ = execTool(t, s, sid, "todo_list", map[string]any{})
	if !ok {
		t.Fatalf("todo_list failed: %+v", out)
	}
	if list, _ := out["todos"].([]any); len(list) != 2 {
		t.Fatalf("todo_list = %+v", out)
	}

	// Replacing the checklist wins over appending.
	if _, ok, _ := execTool(t, s, sid, "todo_write", map[string]any{
		"items": []map[string]any{{"text": "只剩一项", "status": "done"}},
	}); !ok {
		t.Fatal("second todo_write failed")
	}
	if todos, _ := s.Store.ListAgentTodos(sid); len(todos) != 1 || todos[0].Status != "done" {
		t.Fatalf("todos after replace = %+v", todos)
	}

	// Empty checklists are rejected rather than silently clearing the ledger.
	if _, ok, _ := execTool(t, s, sid, "todo_write", map[string]any{"items": []any{}}); ok {
		t.Fatal("empty todo_write should fail")
	}
}

func TestOverwriteRequiresOperatorConfirmation(t *testing.T) {
	s := newAgentServer(t)
	sid, _ := s.Store.CreateChatSession("")
	tid, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "共用模板", Subject: "旧主题", HTML: "<p>old</p>"})

	args := map[string]any{"name": "共用模板", "subject": "新主题", "html": "<p>new</p>"}
	out, ok, note := execTool(t, s, sid, "create_email_template", args)
	if !ok || out["status"] != "awaiting_user_confirmation" || !strings.Contains(note, "等待确认") {
		t.Fatalf("overwrite should await confirmation: %+v ok=%v note=%q", out, ok, note)
	}
	if tpl, _ := s.Store.GetTemplate(tid); tpl.Subject != "旧主题" {
		t.Fatalf("template was overwritten before confirmation: %+v", tpl)
	}

	// The console endpoint replays the exact original arguments.
	body, _ := json.Marshal(map[string]any{"id": out["confirm_id"], "session_id": sid})
	rr := httptest.NewRecorder()
	s.adminChatActionConfirm(rr, httptest.NewRequest(http.MethodPost, "/__admin/api/chat/action/confirm", strings.NewReader(string(body))))
	if rr.Code != 200 {
		t.Fatalf("confirm handler = %d %s", rr.Code, rr.Body.String())
	}
	if tpl, _ := s.Store.GetTemplate(tid); tpl.Subject != "新主题" {
		t.Fatalf("approved overwrite did not run: %+v", tpl)
	}
}

func TestOverwriteCancelLeavesObjectUntouched(t *testing.T) {
	s := newAgentServer(t)
	sid, _ := s.Store.CreateChatSession("")
	pid, _ := s.Store.UpsertPage(store.LandingPage{Name: "登录页", Kind: "template", Body: testLandingBody}, nil)

	out, ok, _ := execTool(t, s, sid, "create_landing_page", map[string]any{
		"name": "登录页", "html": `<p>replaced</p>`,
	})
	if !ok || out["status"] != "awaiting_user_confirmation" {
		t.Fatalf("expected confirmation, got %+v ok=%v", out, ok)
	}
	body, _ := json.Marshal(map[string]any{"id": out["confirm_id"], "session_id": sid, "cancel": true})
	rr := httptest.NewRecorder()
	s.adminChatActionConfirm(rr, httptest.NewRequest(http.MethodPost, "/__admin/api/chat/action/confirm", strings.NewReader(string(body))))
	if rr.Code != 200 {
		t.Fatalf("cancel handler = %d %s", rr.Code, rr.Body.String())
	}
	if p, _ := s.Store.GetPage(pid); strings.Contains(p.Body, "replaced") {
		t.Fatalf("canceled overwrite still modified the page: %q", p.Body)
	}
}

func TestCreateLandingPageAutoValidates(t *testing.T) {
	s := newAgentServer(t)
	out, ok, note := execTool(t, s, 0, "create_landing_page", map[string]any{
		"name": "坏页面", "html": `<html><body><p>缺少表单</p></body></html>`,
	})
	if ok || !strings.Contains(note, "自检") {
		t.Fatalf("invalid page should fail self-check: %+v ok=%v note=%q", out, ok, note)
	}
	v, _ := out["validation"].(map[string]any)
	if v == nil || len(v["errors"].([]any)) == 0 {
		t.Fatalf("validation missing errors: %+v", out)
	}
}

func TestSendCampaignRefusesInvalidLandingPage(t *testing.T) {
	s := newAgentServer(t)
	tplID, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	pageID, _ := s.Store.UpsertPage(store.LandingPage{Name: "bad", Kind: "template", Body: "<p>x</p>"}, nil)
	gid, _ := s.Store.CreateGroup("g")
	_, _ = s.Store.AddTargetsToGroup(gid, []store.Target{{Email: "a@example.com"}})
	pid, _ := s.Store.UpsertSendingProfile(store.SendingProfile{Name: "p", Host: "127.0.0.1", Port: 25, TLSMode: "none", Username: "u", FromEmail: "it@example.com"})
	campID, _ := s.Store.CreateCampaign(store.Campaign{Name: "c", EmailTemplateID: tplID, LandingPageID: pageID, SendingProfileID: pid}, []int64{gid})

	out, ok, note := execTool(t, s, 0, "send_campaign", map[string]any{"campaign_id": campID})
	if ok || !strings.Contains(fmt.Sprint(out["error"]), "自检") || !strings.Contains(note, "拒绝发送") {
		t.Fatalf("invalid page must block send: %+v ok=%v note=%q", out, ok, note)
	}

	dry, dok, _ := execTool(t, s, 0, "dry_run_campaign", map[string]any{"campaign_id": campID})
	if dok {
		t.Fatalf("dry run should fail on invalid page: %+v", dry)
	}
	if errs, _ := dry["errors"].([]any); len(errs) == 0 || !strings.Contains(fmt.Sprint(errs), "落地页自检") {
		t.Fatalf("dry run errors = %+v", dry["errors"])
	}
}

func TestExtractToolImageStripsPayload(t *testing.T) {
	raw := `{"page_id":7,"width":10,"_image":"data:image/jpeg;base64,QUJD"}`
	rest, img := extractToolImage(raw)
	if img != "data:image/jpeg;base64,QUJD" {
		t.Fatalf("image = %q", img)
	}
	if strings.Contains(rest, "_image") || strings.Contains(rest, "QUJD") {
		t.Fatalf("base64 leaked into text context: %s", rest)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(rest), &obj); err != nil || obj["page_id"].(float64) != 7 {
		t.Fatalf("stripped JSON = %s", rest)
	}
	if rest2, img2 := extractToolImage(`{"ok":true}`); img2 != "" || rest2 != `{"ok":true}` {
		t.Fatalf("plain result changed: %q %q", rest2, img2)
	}
}

func TestAutoRepairNudgeTargetsFailedSelfCheck(t *testing.T) {
	tc := llm.ToolCall{}
	tc.Function.Name = "validate_page"
	nudge := autoRepairNudge([]llm.ToolCall{tc}, []toolOutcome{{ok: false}})
	if !strings.Contains(nudge, "自检") {
		t.Fatalf("nudge = %q", nudge)
	}
	if got := autoRepairNudge([]llm.ToolCall{tc}, []toolOutcome{{ok: true}}); got != "" {
		t.Fatalf("passing self-check should not nudge: %q", got)
	}
}

func TestRunAgentFallsBackWhenImagesRejected(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		mu.Unlock()
		if strings.Contains(string(body), `"image_url"`) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":{"message":"image input unsupported"}}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"已看到\"},\"finish_reason\":null}]}\n\n")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":1,\"total_tokens\":4}}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
		f.Flush()
	}))
	defer srv.Close()

	s := newAgentServer(t)
	s.LLM = llm.New(srv.URL, "", "m")
	sid, _ := s.Store.CreateChatSession("")
	history := []llm.Message{{Role: "user", Content: "看截图", Images: []string{"data:image/jpeg;base64,QUJD"}}}

	var deltas []string
	content, _, err := s.runAgent(context.Background(), s.LLM, "", sid, history, func(v any) error {
		if m, ok := v.(map[string]any); ok {
			if d, ok := m["delta"].(string); ok {
				deltas = append(deltas, d)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("runAgent: %v", err)
	}
	if content != "已看到" {
		t.Fatalf("content = %q", content)
	}
	if len(bodies) != 2 || !strings.Contains(bodies[0], `"image_url"`) || strings.Contains(bodies[1], `"image_url"`) {
		t.Fatalf("expected one image attempt then a text-only retry: %d bodies", len(bodies))
	}
	if !strings.Contains(strings.Join(deltas, ""), "图片输入") {
		t.Fatalf("fallback was not announced: %v", deltas)
	}
}

func TestReadOnlyToolsetExcludesWritesAndRecursion(t *testing.T) {
	all := agentTools()
	ro := readOnlyAgentTools()
	if len(ro) == 0 || len(ro) >= len(all) {
		t.Fatalf("read-only subset = %d of %d", len(ro), len(all))
	}
	for _, def := range ro {
		name := def.Function.Name
		if name == "dispatch_subagents" {
			t.Fatal("sub-agents must not be able to recurse")
		}
		spec, ok := agentToolMeta(name)
		if !ok || !spec.ReadOnly {
			t.Fatalf("non-read-only tool in subset: %s", name)
		}
	}
}

func TestDispatchSubagentsRunsReadOnlyChildren(t *testing.T) {
	var mu sync.Mutex
	writes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []struct {
				Role string `json:"role"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		sawTool := false
		for _, m := range req.Messages {
			if m.Role == "tool" {
				sawTool = true
			}
		}
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		if !sawTool {
			// Every child tries a write tool first; the runner must refuse it.
			mu.Lock()
			writes++
			mu.Unlock()
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"type\":\"function\",\"function\":{\"name\":\"create_group\",\"arguments\":\"{\\\"name\\\":\\\"不该出现\\\",\\\"targets\\\":[{\\\"email\\\":\\\"a@example.com\\\"}]}\"}}]},\"finish_reason\":null}]}\n\n")
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n")
		} else {
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"结论：已核验\\n证据：- 只读\"},\"finish_reason\":null}]}\n\n")
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2,\"total_tokens\":7}}\n\n")
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		f.Flush()
	}))
	defer srv.Close()

	s := newAgentServer(t)
	s.LLM = llm.New(srv.URL, "", "m")
	ctx := withAgentRuntime(context.Background(), s.LLM, "m")
	reports := s.dispatchSubagents(ctx, []subagentTask{
		{Title: "核验 A", Instruction: "检查目标组 A"},
		{Title: "核验 B", Instruction: "检查目标组 B"},
	})
	if len(reports) != 2 {
		t.Fatalf("reports = %+v", reports)
	}
	for i, rep := range reports {
		if rep.Error != "" || !strings.Contains(rep.Result, "已核验") {
			t.Fatalf("report %d = %+v", i, rep)
		}
		if rep.ToolCalls != 1 {
			t.Fatalf("report %d tool calls = %d", i, rep.ToolCalls)
		}
	}
	if writes != 2 {
		t.Fatalf("children did not attempt writes: %d", writes)
	}
	if groups, _ := s.Store.ListGroups(); len(groups) != 0 {
		t.Fatalf("sub-agent write leaked into the store: %+v", groups)
	}
}
