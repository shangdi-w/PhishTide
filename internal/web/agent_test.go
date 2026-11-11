package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"phishsim/internal/core/config"
	"phishsim/internal/core/store"
	"phishsim/internal/features/llm"
)

func newAgentServer(t *testing.T) *Server {
	t.Helper()
	return &Server{Cfg: &config.Config{}, Store: newConfigStore(t), LLM: llm.New("", "", "m")}
}

// toolCall builds a tool call whose arguments are JSON-encoded from args.
func toolCall(t *testing.T, name string, args any) llm.ToolCall {
	t.Helper()
	b, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	tc := llm.ToolCall{ID: "call_test", Type: "function"}
	tc.Function.Name = name
	tc.Function.Arguments = string(b)
	return tc
}

func execTool(t *testing.T, s *Server, sessionID int64, name string, args any) (map[string]any, bool, string) {
	t.Helper()
	raw, ok, note := s.executeTool(context.Background(), sessionID, toolCall(t, name, args), func(any) error { return nil })
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("tool result is not JSON: %s", raw)
	}
	return out, ok, note
}

func TestExecuteToolBuildsEmailTemplateAndAttachesUpload(t *testing.T) {
	s := newAgentServer(t)
	sid, err := s.Store.CreateChatSession("")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := s.Store.AddChatUpload(store.ChatUpload{SessionID: sid, Name: "附件.pdf", ContentType: "application/pdf", Body: []byte("%PDF")})
	if err != nil {
		t.Fatal(err)
	}

	out, ok, _ := execTool(t, s, sid, "create_email_template", map[string]any{
		"name": "季度通知", "subject": "请重置密码",
		"html":       `<html><body><a href="{{.TrackingURL}}">重置</a></body></html>`,
		"upload_ids": []int64{uid},
	})
	if !ok {
		t.Fatalf("create_email_template failed: %+v", out)
	}
	tid := int64(out["template_id"].(float64))
	tpl, err := s.Store.GetTemplate(tid)
	if err != nil || tpl.Name != "季度通知" || !strings.Contains(tpl.HTML, "TrackingURL") {
		t.Fatalf("template = %+v, err = %v", tpl, err)
	}
	atts, _ := s.Store.ListTemplateAttachments(tid)
	if len(atts) != 1 || atts[0].Name != "附件.pdf" {
		t.Fatalf("attachments = %+v", atts)
	}

	// Updating by id must not create a second template.
	out, ok, _ = execTool(t, s, sid, "update_email_template", map[string]any{"template_id": tid, "name": "季度通知-v2"})
	if !ok {
		t.Fatalf("update failed: %+v", out)
	}
	if list, _ := s.Store.ListTemplates(); len(list) != 1 || list[0].Name != "季度通知-v2" {
		t.Fatalf("templates = %+v", list)
	}
}

func TestExecuteToolCreateAndBeautifyLandingPage(t *testing.T) {
	s := newAgentServer(t)
	out, ok, _ := execTool(t, s, 0, "create_landing_page", map[string]any{
		"name": "登录页", "html": `<html><body><form action="__SUBMIT_URL__"><input name="email"></form></body></html>`,
	})
	if !ok {
		t.Fatalf("create_landing_page failed: %+v", out)
	}
	pid := int64(out["page_id"].(float64))
	out, ok, _ = execTool(t, s, 0, "update_landing_page", map[string]any{
		"page_id": pid, "html": `<html><body style="background:#123"><form action="__SUBMIT_URL__"><input name="email"><input name="password"></form></body></html>`,
	})
	if !ok {
		t.Fatalf("update_landing_page failed: %+v", out)
	}
	p, err := s.Store.GetPage(pid)
	if err != nil || !strings.Contains(p.Body, "background:#123") || !strings.Contains(p.Body, `name="password"`) {
		t.Fatalf("page = %+v, err = %v", p, err)
	}
	if list, _ := s.Store.ListPages(); len(list) != 1 {
		t.Fatalf("pages = %+v", list)
	}
}

func TestCreateSendingProfileInfersHostAndPort(t *testing.T) {
	s := newAgentServer(t)
	out, ok, note := execTool(t, s, 0, "create_sending_profile", map[string]any{
		"name": "QQ 发件", "username": "ops@qq.com", "password": "授权码", "port": 465,
	})
	if !ok {
		t.Fatalf("create_sending_profile failed: %+v", out)
	}
	if out["host"] != "smtp.qq.com" || out["tls_mode"] != "ssl" {
		t.Fatalf("inferred profile = %+v", out)
	}
	if !strings.Contains(note, "smtp.qq.com:465") {
		t.Fatalf("note = %q", note)
	}

	// Without an email there is nothing to infer from.
	out, ok, _ = execTool(t, s, 0, "create_sending_profile", map[string]any{"name": "x", "username": "ops", "password": "p"})
	if ok || !strings.Contains(fmt.Sprint(out["error"]), "host") {
		t.Fatalf("expected host error, got %+v", out)
	}
}

func TestExecuteToolValidation(t *testing.T) {
	s := newAgentServer(t)
	cases := []struct {
		name string
		args any
	}{
		{"create_group", map[string]any{"name": "g", "targets": []map[string]any{{"email": "no-at-sign"}}}},
		{"create_sending_profile", map[string]any{"name": "p", "host": "smtp.example.com", "port": 70000, "username": "u", "password": "p"}},
		{"create_campaign", map[string]any{"name": "c"}},
		{"not_a_tool", map[string]any{}},
	}
	for _, c := range cases {
		out, ok, _ := execTool(t, s, 0, c.name, c.args)
		if ok || out["error"] == nil {
			t.Fatalf("%s with bad args should fail: %+v", c.name, out)
		}
	}
}

// testLandingBody is a landing page that passes the self-check.
const testLandingBody = `<form action="__SUBMIT_URL__" method="post"><input name="username"><input type="password" name="password"><button>登录</button></form>`

func agentCampaignFixtures(t *testing.T, s *Server) (campID int64) {
	t.Helper()
	tplID, err := s.Store.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "请重置密码", HTML: "<p>x</p>"})
	if err != nil {
		t.Fatal(err)
	}
	pageID, err := s.Store.UpsertPage(store.LandingPage{Name: "p", Kind: "template", Body: testLandingBody, ContentType: "text/html"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := s.Store.CreateGroup("g")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.AddTargetsToGroup(gid, []store.Target{{Email: "a@example.com"}, {Email: "b@example.com"}}); err != nil {
		t.Fatal(err)
	}
	pid, err := s.Store.UpsertSendingProfile(store.SendingProfile{
		Name: "p", Host: "127.0.0.1", Port: 25, TLSMode: "none",
		Username: "u", FromEmail: "it@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	campID, err = s.Store.CreateCampaign(store.Campaign{Name: "演练", EmailTemplateID: tplID, LandingPageID: pageID, SendingProfileID: pid}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	return campID
}

func TestSendCampaignNeverSendsWithoutConfirm(t *testing.T) {
	s := newAgentServer(t)
	sid, _ := s.Store.CreateChatSession("")
	campID := agentCampaignFixtures(t, s)

	var events []any
	raw, ok, note := s.executeTool(context.Background(), sid,
		toolCall(t, "send_campaign", map[string]any{"campaign_id": campID}),
		func(v any) error { events = append(events, v); return nil })
	if !ok {
		t.Fatalf("send_campaign failed: %s", raw)
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(raw), &out)
	if out["status"] != "awaiting_user_confirmation" || out["targets"].(float64) != 2 {
		t.Fatalf("result = %v", out)
	}
	if !strings.Contains(note, "等待确认") {
		t.Fatalf("note = %q", note)
	}
	var confirm pendingConfirm
	found := false
	for _, e := range events {
		m, _ := e.(map[string]any)
		if c, ok := m["confirm"].(pendingConfirm); ok {
			confirm = c
			found = true
		}
	}
	if !found || confirm.Campaign != campID || confirm.Targets != 2 {
		t.Fatalf("confirm event = %+v (found %v)", confirm, found)
	}
	// Nothing may have been handed to SMTP yet.
	results, _ := s.Store.ListResults(campID)
	for _, r := range results {
		if r.Sent {
			t.Fatal("send_campaign sent mail before the operator confirmed")
		}
	}
	// The confirmation belongs to the session that prepared it.
	if _, ok := s.takeConfirm(confirm.ID, sid+1); ok {
		t.Fatal("confirmation was consumable from another session")
	}
	if _, ok := s.takeConfirm(confirm.ID, sid); !ok {
		t.Fatal("owner could not consume its confirmation")
	}
}

func TestSendCampaignWithoutProfileIsRefused(t *testing.T) {
	s := newAgentServer(t)
	tplID, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	pageID, _ := s.Store.UpsertPage(store.LandingPage{Name: "p", Kind: "template", Body: testLandingBody}, nil)
	gid, _ := s.Store.CreateGroup("g")
	_, _ = s.Store.AddTargetsToGroup(gid, []store.Target{{Email: "a@example.com"}})
	campID, _ := s.Store.CreateCampaign(store.Campaign{Name: "c", EmailTemplateID: tplID, LandingPageID: pageID}, []int64{gid})

	out, ok, _ := execTool(t, s, 0, "send_campaign", map[string]any{"campaign_id": campID})
	if ok || !strings.Contains(fmt.Sprint(out["error"]), "发件账号") {
		t.Fatalf("expected refusal, got %+v", out)
	}
}

func TestTrimAgentHistoryKeepsValidToolWindow(t *testing.T) {
	msgs := []llm.Message{
		{Role: "user", Content: "old"},
		{Role: "assistant", ToolCalls: []llm.ToolCall{{ID: "c1"}}},
		{Role: "tool", ToolCallID: "c1", Content: "result"},
		{Role: "assistant", Content: "done"},
		{Role: "user", Content: "new"},
	}
	// A window that starts mid-tool-sequence must drop the orphaned tool turn.
	out := trimAgentHistory(msgs, 2, 1000)
	if len(out) == 0 || out[0].Role == "tool" {
		t.Fatalf("trimmed window starts with a tool result: %+v", out)
	}

	out = trimAgentHistory(msgs, 60, 1000)
	if len(out) != len(msgs) || out[0].Content != "old" {
		t.Fatalf("small history was altered: %+v", out)
	}
}

func TestRunAgentExecutesToolThenAnswers(t *testing.T) {
	var rounds int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rounds++
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		if rounds == 1 {
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"type\":\"function\",\"function\":{\"name\":\"create_group\",\"arguments\":\"{\\\"name\\\":\\\"AI 组\\\",\\\"targets\\\":[{\\\"email\\\":\\\"a@example.com\\\"}]}\"}}]},\"finish_reason\":null}]}\n\n")
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2,\"total_tokens\":12}}\n\n")
		} else {
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"已完成\"},\"finish_reason\":null}]}\n\n")
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":20,\"completion_tokens\":3,\"total_tokens\":23}}\n\n")
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		f.Flush()
	}))
	defer srv.Close()

	s := newAgentServer(t)
	s.LLM = llm.New(srv.URL, "", "m")
	sid, _ := s.Store.CreateChatSession("t")

	var deltas []string
	var toolEvents []map[string]any
	emit := func(v any) error {
		m, _ := v.(map[string]any)
		if d, ok := m["delta"].(string); ok {
			deltas = append(deltas, d)
		}
		if tv, ok := m["tool"].(map[string]any); ok {
			toolEvents = append(toolEvents, tv)
		}
		return nil
	}
	history := []llm.Message{{Role: "user", Content: "建一个测试组"}}
	content, usage, err := s.runAgent(context.Background(), s.LLM, "", sid, history, emit)
	if err != nil {
		t.Fatalf("runAgent: %v", err)
	}
	if content != "已完成" || strings.Join(deltas, "") != "已完成" {
		t.Fatalf("content = %q deltas = %v", content, deltas)
	}
	if usage.TotalTokens != 35 {
		t.Fatalf("usage not accumulated across rounds: %+v", usage)
	}
	groups, _ := s.Store.ListGroups()
	if len(groups) != 1 || groups[0].Name != "AI 组" {
		t.Fatalf("tool did not run: %+v", groups)
	}
	if len(toolEvents) != 2 || toolEvents[0]["status"] != "start" || toolEvents[1]["status"] != "done" {
		t.Fatalf("tool events = %+v", toolEvents)
	}
	msgs, _ := s.Store.ListChatMessages(sid)
	var roles []string
	for _, m := range msgs {
		roles = append(roles, m.Role)
	}
	// assistant(tool_calls), tool(result), assistant(final)
	if strings.Join(roles, ",") != "assistant,tool,assistant" {
		t.Fatalf("persisted roles = %v", roles)
	}
}

func TestChatSessionHandlers(t *testing.T) {
	s := newAgentServer(t)

	rr := httptest.NewRecorder()
	s.adminChatSessions(rr, httptest.NewRequest(http.MethodPost, "/__admin/api/chat/sessions", strings.NewReader(`{"title":"名单导入"}`)))
	if rr.Code != 200 {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	if created.ID == 0 {
		t.Fatal("session id missing")
	}
	_, _ = s.Store.AppendChatMessage(created.ID, "user", "你好", `{"role":"user","content":"你好"}`)

	rr = httptest.NewRecorder()
	s.adminChatSessions(rr, httptest.NewRequest(http.MethodGet, "/__admin/api/chat/sessions", nil))
	if !strings.Contains(rr.Body.String(), "名单导入") {
		t.Fatalf("list: %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	s.adminChatSession(rr, httptest.NewRequest(http.MethodGet, "/__admin/api/chat/sessions/1", nil), created.ID)
	if !strings.Contains(rr.Body.String(), "你好") {
		t.Fatalf("get: %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	s.adminChatSession(rr, httptest.NewRequest(http.MethodPatch, "/__admin/api/chat/sessions/1", strings.NewReader(`{"title":"新标题"}`)), created.ID)
	if rr.Code != 200 {
		t.Fatalf("rename: %d %s", rr.Code, rr.Body.String())
	}
	if sess, _ := s.Store.GetChatSession(created.ID); sess.Title != "新标题" {
		t.Fatalf("title = %q", sess.Title)
	}

	rr = httptest.NewRecorder()
	s.adminChatSession(rr, httptest.NewRequest(http.MethodDelete, "/__admin/api/chat/sessions/1", nil), created.ID)
	if rr.Code != 200 {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := s.Store.GetChatSession(created.ID); err == nil {
		t.Fatal("session survived DELETE")
	}
}

func TestChatUploadStoresCSVAndPreviewsRecipients(t *testing.T) {
	s := newAgentServer(t)
	sid, _ := s.Store.CreateChatSession("")

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("session_id", fmt.Sprint(sid))
	part, _ := mw.CreateFormFile("file", "名单.csv")
	_, _ = part.Write([]byte("email,first_name\na@example.com,A\nb@example.com,B\n"))
	_ = mw.Close()

	r := httptest.NewRequest(http.MethodPost, "/__admin/api/chat/upload", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	s.adminChatUpload(rr, r)
	if rr.Code != 200 {
		t.Fatalf("upload: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "识别到 2 个收件人") {
		t.Fatalf("preview missing: %s", rr.Body.String())
	}
	uploads, _ := s.Store.ListChatUploads(sid)
	if len(uploads) != 1 || uploads[0].Name != "名单.csv" {
		t.Fatalf("uploads = %+v", uploads)
	}
}

func TestImportCSVToolUsesUploadOfSameSession(t *testing.T) {
	s := newAgentServer(t)
	sid, _ := s.Store.CreateChatSession("")
	uid, _ := s.Store.AddChatUpload(store.ChatUpload{SessionID: sid, Name: "名单.csv", ContentType: "text/csv",
		Body: []byte("email\na@example.com\nb@example.com\n")})

	out, ok, _ := execTool(t, s, sid, "import_csv_to_group", map[string]any{"group_name": "导入组", "upload_id": uid})
	if !ok || out["targets_added"].(float64) != 2 {
		t.Fatalf("import failed: %+v", out)
	}
	// Another session cannot reference the upload.
	tpl, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	other, _ := s.Store.CreateChatSession("")
	out, ok, _ = execTool(t, s, other, "add_template_attachments", map[string]any{"template_id": tpl, "upload_ids": []int64{uid}})
	if ok || !strings.Contains(fmt.Sprint(out["error"]), "不属于当前会话") {
		t.Fatalf("cross-session upload was accepted: %+v", out)
	}
}

func TestValidatePageReportsProblems(t *testing.T) {
	s := newAgentServer(t)
	pid, _ := s.Store.UpsertPage(store.LandingPage{
		Name: "坏页面", Kind: "template",
		Body:               `<html><body><form action="https://evil.example/login"></form><img src="https://cdn.example/a.png"></body></html>`,
		CaptureCredentials: true,
	}, nil)
	out, ok, note := execTool(t, s, 0, "validate_page", map[string]any{"page_id": pid})
	if ok || out["ok"] != false {
		t.Fatalf("expected validation failure: %+v", out)
	}
	if !strings.Contains(fmt.Sprint(out["errors"]), "输入框") || !strings.Contains(note, "问题") {
		t.Fatalf("missing field error: %+v note=%q", out, note)
	}
	if !strings.Contains(fmt.Sprint(out["warnings"]), "外部地址") {
		t.Fatalf("missing external action warning: %+v", out)
	}
	if !strings.Contains(fmt.Sprint(out["external_resources"]), "cdn.example") {
		t.Fatalf("missing external resource: %+v", out)
	}

	// A properly wired page passes.
	good, _ := s.Store.UpsertPage(store.LandingPage{
		Name: "好页面", Kind: "template",
		Body:               `<html><body><form method="post" action="__SUBMIT_URL__"><input name="email"><input type="password" name="password"></form></body></html>`,
		CaptureCredentials: true, CapturePasswords: true,
	}, nil)
	out, ok, _ = execTool(t, s, 0, "validate_page", map[string]any{"page_id": good})
	if !ok || out["ok"] != true || out["has_submit_url"] != true || out["has_password_input"] != true {
		t.Fatalf("good page failed validation: %+v", out)
	}
	if fields, _ := out["fields"].([]any); len(fields) != 2 {
		t.Fatalf("fields = %+v", out["fields"])
	}
}

func TestValidatePageRejectsMissingPage(t *testing.T) {
	s := newAgentServer(t)
	out, ok, _ := execTool(t, s, 0, "validate_page", map[string]any{"page_id": 999})
	if ok || !strings.Contains(fmt.Sprint(out["error"]), "不存在") {
		t.Fatalf("expected missing page error: %+v", out)
	}
}

func TestDryRunCampaignReportsAndDoesNotSend(t *testing.T) {
	s := newAgentServer(t)
	s.Cfg.PublicURL = "https://phish.example.com"
	tpl, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "请登录", HTML: `<p><a href="{{.TrackingURL}}">登录</a></p>`, Text: "登录"})
	page, _ := s.Store.UpsertPage(store.LandingPage{Name: "p", Kind: "template", Body: `<form action="__SUBMIT_URL__"><input name="email"></form>`, CaptureCredentials: true}, nil)
	gid, _ := s.Store.CreateGroup("g")
	_, _ = s.Store.AddTargetsToGroup(gid, []store.Target{{Email: "a@example.com"}, {Email: "b@example.com"}})
	prof, _ := s.Store.UpsertSendingProfile(store.SendingProfile{Name: "smtp", Host: "127.0.0.1", Port: 2525, TLSMode: "none", FromEmail: "ops@example.com"})
	camp, _ := s.Store.CreateCampaign(store.Campaign{Name: "c", EmailTemplateID: tpl, LandingPageID: page, SendingProfileID: prof}, []int64{gid})

	out, ok, note := execTool(t, s, 0, "dry_run_campaign", map[string]any{"campaign_id": camp})
	if !ok || out["ok"] != true {
		t.Fatalf("dry run failed: %+v note=%q", out, note)
	}
	if out["pending"].(float64) != 2 || out["previews"].(float64) != 2 {
		t.Fatalf("counts = %+v", out)
	}
	res, _ := s.Store.ListResults(camp)
	for _, r := range res {
		if r.Sent {
			t.Fatal("dry run marked a recipient as sent")
		}
	}

	// Without a sending profile the dry run still works but warns.
	camp2, _ := s.Store.CreateCampaign(store.Campaign{Name: "c2", EmailTemplateID: tpl, LandingPageID: page}, []int64{gid})
	out, ok, _ = execTool(t, s, 0, "dry_run_campaign", map[string]any{"campaign_id": camp2})
	if !ok || !strings.Contains(fmt.Sprint(out["warnings"]), "未绑定发件账号") {
		t.Fatalf("expected profile warning: %+v", out)
	}
}

func TestDryRunCampaignBlocksOverLimit(t *testing.T) {
	s := newAgentServer(t)
	s.Cfg.MaxSendTargets = 1
	tpl, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	page, _ := s.Store.UpsertPage(store.LandingPage{Name: "p", Kind: "template", Body: "<p>x</p>"}, nil)
	gid, _ := s.Store.CreateGroup("g")
	_, _ = s.Store.AddTargetsToGroup(gid, []store.Target{{Email: "a@example.com"}, {Email: "b@example.com"}})
	camp, _ := s.Store.CreateCampaign(store.Campaign{Name: "c", EmailTemplateID: tpl, LandingPageID: page}, []int64{gid})
	out, ok, _ := execTool(t, s, 0, "dry_run_campaign", map[string]any{"campaign_id": camp})
	if ok || !strings.Contains(fmt.Sprint(out["errors"]), "超过单次上限") {
		t.Fatalf("expected limit error: %+v", out)
	}
}

// startSMTPSink runs a minimal plaintext SMTP server and returns its address
// plus a channel that receives one delivered DATA payload.
func startSMTPSink(t *testing.T) (string, int, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan string, 8)
	handle := func(conn net.Conn) {
		defer conn.Close()
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)
		say := func(s string) {
			_, _ = w.WriteString(s + "\r\n")
			_ = w.Flush()
		}
		say("220 sink")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					inData = false
					say("250 queued")
					select {
					case got <- data.String():
					default:
					}
					continue
				}
				data.WriteString(line + "\n")
				continue
			}
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				say("250-sink")
				say("250 SIZE 10485760")
			case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
				say("250 OK")
			case strings.HasPrefix(line, "DATA"):
				say("354 send it")
				inData = true
			case strings.HasPrefix(line, "QUIT"):
				say("221 bye")
				return
			default:
				say("250 OK")
			}
		}
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, got
}

func TestTestSendDeliversOneMailToProfileAddress(t *testing.T) {
	host, port, got := startSMTPSink(t)
	s := newAgentServer(t)
	tpl, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "重置密码", HTML: `<p><a href="{{.TrackingURL}}">重置</a></p>`, Text: "重置"})
	prof, _ := s.Store.UpsertSendingProfile(store.SendingProfile{
		Name: "sink", Host: host, Port: port, TLSMode: "none", FromEmail: "ops@example.com",
	})
	out, ok, note := execTool(t, s, 0, "test_send", map[string]any{"profile_id": prof, "template_id": tpl})
	if !ok {
		t.Fatalf("test_send failed: %+v note=%q", out, note)
	}
	if out["to"] != "ops@example.com" || out["attachments"].(float64) != 0 {
		t.Fatalf("test send result = %+v", out)
	}
	select {
	case mail := <-got:
		if !strings.Contains(mail, "To: ops@example.com") || !strings.Contains(mail, "MIME-Version: 1.0") {
			t.Fatalf("unexpected mail: %s", mail)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sink received no mail")
	}
}

func TestTrimAgentHistorySummarizesDroppedTurns(t *testing.T) {
	msgs := []llm.Message{
		{Role: "user", Content: "发件人是 ops@example.com，只发给研发部"},
		{Role: "assistant", Content: "收到"},
		{Role: "user", Content: "继续"},
		{Role: "assistant", Content: strings.Repeat("很长的回答", 50)},
		{Role: "user", Content: "最后一句"},
	}
	out := trimAgentHistory(msgs, 2, 50)
	if len(out) == 0 || out[0].Role != "system" {
		t.Fatalf("expected a leading summary, got %+v", out)
	}
	if !strings.Contains(out[0].Content, "ops@example.com") {
		t.Fatalf("summary lost the early constraint: %q", out[0].Content)
	}
}

func TestAgentToolSchemasAreValidJSON(t *testing.T) {
	tools := agentTools()
	if len(tools) < 20 {
		t.Fatalf("expected the full tool set, got %d", len(tools))
	}
	names := map[string]bool{}
	for _, tool := range tools {
		if tool.Function.Name == "" || tool.Function.Description == "" {
			t.Fatalf("tool missing name/description: %+v", tool.Function)
		}
		names[tool.Function.Name] = true
		var params any
		if err := json.Unmarshal(tool.Function.Parameters, &params); err != nil {
			t.Fatalf("tool %s has invalid parameter schema: %v\n%s", tool.Function.Name, err, tool.Function.Parameters)
		}
	}
	for _, want := range []string{"validate_page", "dry_run_campaign", "test_send"} {
		if !names[want] {
			t.Fatalf("missing tool %s", want)
		}
	}
	if _, err := json.Marshal(tools); err != nil {
		t.Fatalf("tools do not marshal: %v", err)
	}
}

func TestFetchURLSummarizesReferencePage(t *testing.T) {
	ref := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><head><title>参考站 登录</title>`+
			`<link rel="stylesheet" href="/site.css">`+
			`<style>body{background:#112233;font-family:"Noto Sans", sans-serif}</style></head>`+
			`<body><form action="/login"><input type="password" name="pwd"></form>`+
			`<a href="https://cdn.example/x.png">x</a></body></html>`)
	}))
	defer ref.Close()

	s := newAgentServer(t)
	out, ok, note := execTool(t, s, 0, "fetch_url", map[string]any{"url": ref.URL})
	if !ok {
		t.Fatalf("fetch_url failed: %+v note=%q", out, note)
	}
	if out["title"] != "参考站 登录" || out["forms"].(float64) != 1 || out["password_inputs"].(float64) != 1 {
		t.Fatalf("reference summary = %+v", out)
	}
	if !strings.Contains(fmt.Sprint(out["colors"]), "#112233") {
		t.Fatalf("colors = %+v", out["colors"])
	}
	if !strings.Contains(fmt.Sprint(out["css"]), "/site.css") {
		t.Fatalf("css = %+v", out["css"])
	}
	if !strings.Contains(fmt.Sprint(out["fonts"]), "Noto Sans") {
		t.Fatalf("fonts = %+v", out["fonts"])
	}
	if !strings.Contains(fmt.Sprint(out["html"]), "<form") {
		t.Fatalf("html missing: %+v", out["html"])
	}
}

func TestFetchURLRejectsPrivateAndNonHTTP(t *testing.T) {
	s := newAgentServer(t)
	s.Cfg.CloneDenyPrivate = true
	out, ok, _ := execTool(t, s, 0, "fetch_url", map[string]any{"url": "http://127.0.0.1:1/x"})
	if ok || !strings.Contains(fmt.Sprint(out["error"]), "内网") {
		t.Fatalf("private target was not refused: %+v", out)
	}
	out, ok, _ = execTool(t, s, 0, "fetch_url", map[string]any{"url": "file:///etc/passwd"})
	if ok || !strings.Contains(fmt.Sprint(out["error"]), "http") {
		t.Fatalf("non-http target was not refused: %+v", out)
	}
}

func TestValidatePageCheckLinksBlocksPrivateTargets(t *testing.T) {
	s := newAgentServer(t)
	pid, _ := s.Store.UpsertPage(store.LandingPage{
		Name: "链接页", Kind: "template",
		Body:               `<form action="__SUBMIT_URL__"><input name="email"></form><img src="http://127.0.0.1:1/a.png">`,
		CaptureCredentials: true,
	}, nil)
	out, _, _ := execTool(t, s, 0, "validate_page", map[string]any{"page_id": pid, "check_links": true})
	links, _ := out["links"].([]any)
	if len(links) != 1 {
		t.Fatalf("links = %+v", out["links"])
	}
	if !strings.Contains(fmt.Sprint(links[0]), "blocked-private") {
		t.Fatalf("private link was probed: %+v", links[0])
	}
	if !strings.Contains(fmt.Sprint(out["warnings"]), "链接不可用") {
		t.Fatalf("missing link warning: %+v", out["warnings"])
	}
}

func TestRunAgentExecutesReadOnlyToolsInParallel(t *testing.T) {
	var rounds int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rounds++
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		if rounds == 1 {
			fmt.Fprint(w, `data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","type":"function","function":{"name":"list_groups","arguments":"{}"}},{"index":1,"id":"c2","type":"function","function":{"name":"list_pages","arguments":"{}"}}]},"finish_reason":null}]}`+"\n\n")
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n")
		} else {
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"完成\"},\"finish_reason\":null}]}\n\n")
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n")
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		f.Flush()
	}))
	defer srv.Close()

	s := newAgentServer(t)
	s.LLM = llm.New(srv.URL, "", "m")
	sid, _ := s.Store.CreateChatSession("")
	var started, done int
	emit := func(v any) error {
		m, _ := v.(map[string]any)
		tv, ok := m["tool"].(map[string]any)
		if !ok {
			return nil
		}
		switch tv["status"] {
		case "start":
			started++
		case "done":
			done++
			if tv["ok"] != true {
				t.Errorf("tool %v failed: %+v", tv["name"], tv)
			}
		}
		return nil
	}
	_, _, err := s.runAgent(context.Background(), s.LLM, "", sid, []llm.Message{{Role: "user", Content: "看看"}}, emit)
	if err != nil {
		t.Fatalf("runAgent: %v", err)
	}
	if started != 2 || done != 2 {
		t.Fatalf("tool events = %d start, %d done", started, done)
	}
	msgs, _ := s.Store.ListChatMessages(sid)
	var toolData []string
	for _, m := range msgs {
		if m.Role == "tool" {
			toolData = append(toolData, m.Data)
		}
	}
	if len(toolData) != 2 || !strings.Contains(toolData[0], "groups") || !strings.Contains(toolData[1], "pages") {
		t.Fatalf("tool results out of order: %+v", toolData)
	}
}

func TestRememberRecallForgetToolsAndPromptInjection(t *testing.T) {
	s := newAgentServer(t)
	out, ok, note := execTool(t, s, 0, "remember", map[string]any{"key": "发件邮箱", "value": "ops@example.com"})
	if !ok || out["saved"] != true || !strings.Contains(note, "已记住") {
		t.Fatalf("remember failed: %+v note=%q", out, note)
	}
	// A second session sees the saved memory in its system prompt.
	if p := s.agentSystemPrompt(""); !strings.Contains(p, "ops@example.com") {
		t.Fatalf("memory not injected into prompt: %s", p)
	}

	out, ok, _ = execTool(t, s, 0, "recall", map[string]any{"query": "example"})
	mems, _ := out["memories"].([]any)
	if !ok || len(mems) != 1 || !strings.Contains(fmt.Sprint(mems[0]), "发件邮箱") {
		t.Fatalf("recall failed: %+v", out)
	}
	out, ok, _ = execTool(t, s, 0, "forget", map[string]any{"key": "发件邮箱"})
	if !ok || out["deleted"] != true {
		t.Fatalf("forget failed: %+v", out)
	}
	if strings.Contains(s.agentSystemPrompt(""), "ops@example.com") {
		t.Fatal("deleted memory still in prompt")
	}
	// Validation
	out, ok, _ = execTool(t, s, 0, "remember", map[string]any{"key": "", "value": "x"})
	if ok || !strings.Contains(fmt.Sprint(out["error"]), "不能为空") {
		t.Fatalf("empty key accepted: %+v", out)
	}
}

func TestSearchWebUsesConfiguredSearxNG(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"results":[{"title":"登录页参考","url":"https://example.com/login","content":"一个简洁的登录页"}]}`)
	}))
	defer srv.Close()

	s := newAgentServer(t)
	out, ok, _ := execTool(t, s, 0, "search_web", map[string]any{"query": "登录页"})
	if ok || !strings.Contains(fmt.Sprint(out["error"]), "未配置") {
		t.Fatalf("search without config should fail: %+v", out)
	}

	s.Cfg.SearchURL = srv.URL
	out, ok, note := execTool(t, s, 0, "search_web", map[string]any{"query": "登录页", "limit": 3})
	if !ok || !strings.Contains(note, "1 条") {
		t.Fatalf("search failed: %+v note=%q", out, note)
	}
	if gotPath != "/search" || gotQuery != "登录页" {
		t.Fatalf("search request = %s q=%q", gotPath, gotQuery)
	}
	results, _ := out["results"].([]any)
	if len(results) != 1 || !strings.Contains(fmt.Sprint(results[0]), "example.com/login") {
		t.Fatalf("results = %+v", results)
	}
}

func TestFetchURLRendersSPA(t *testing.T) {
	if os.Getenv("PHISH_TEST_RENDER") == "" {
		t.Skip("set PHISH_TEST_RENDER=1 to exercise the headless browser")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>SPA 参考</title></head><body><div id="root"></div>`+
			`<script>document.getElementById('root').innerHTML='<form action="/go"><input type="password" name="pwd"></form><style>body{background:#abcdef}</style>';</script></body></html>`)
	}))
	defer srv.Close()

	s := newAgentServer(t)
	out, ok, _ := execTool(t, s, 0, "fetch_url", map[string]any{"url": srv.URL, "render": true})
	if !ok {
		t.Fatalf("render failed: %+v", out)
	}
	if out["forms"].(float64) != 1 || out["password_inputs"].(float64) != 1 {
		t.Fatalf("SPA was not rendered: %+v", out)
	}
	if !strings.Contains(fmt.Sprint(out["colors"]), "#abcdef") {
		t.Fatalf("rendered style missing: %+v", out["colors"])
	}
}
