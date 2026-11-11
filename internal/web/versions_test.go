package web

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"phishsim/internal/core/store"
	"phishsim/internal/features/llm"
)

func TestContentVersionsSnapshotAndRestore(t *testing.T) {
	s := newAgentServer(t)
	id, err := s.Store.UpsertTemplate(store.EmailTemplate{Name: "v1", Subject: "第一次", HTML: "<p>1</p>"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.UpdateTemplate(store.EmailTemplate{ID: id, Name: "v1", Subject: "第二次", HTML: "<p>2</p>"}); err != nil {
		t.Fatal(err)
	}
	list, err := s.Store.ListContentVersions(store.VersionEmailTemplate, id, 20)
	if err != nil || len(list) != 2 {
		t.Fatalf("versions = %+v, err = %v", list, err)
	}
	if list[0].Action != "update" || list[1].Action != "create" {
		t.Fatalf("actions = %q, %q", list[0].Action, list[1].Action)
	}

	// Roll back to the original snapshot.
	v, err := s.Store.RestoreContentVersion(list[1].ID)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if v.Kind != store.VersionEmailTemplate || v.ObjectID != id {
		t.Fatalf("restored version = %+v", v)
	}
	got, err := s.Store.GetTemplate(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "第一次" || got.HTML != "<p>1</p>" {
		t.Fatalf("template after rollback = %+v", got)
	}
	// The rollback itself is versioned.
	list, _ = s.Store.ListContentVersions(store.VersionEmailTemplate, id, 20)
	if len(list) != 3 || list[0].Action != "rollback" {
		t.Fatalf("versions after rollback = %+v", list)
	}
}

func TestContentVersionPrunedAndDeletedWithObject(t *testing.T) {
	s := newAgentServer(t)
	id, err := s.Store.UpsertTemplate(store.EmailTemplate{Name: "p", Subject: "s", HTML: "<p>x</p>"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		if err := s.Store.UpdateTemplate(store.EmailTemplate{ID: id, Name: "p", Subject: "s", HTML: "<p>x</p>"}); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := s.Store.ListContentVersions(store.VersionEmailTemplate, id, 100)
	if len(list) != 20 {
		t.Fatalf("kept %d versions, want 20", len(list))
	}
	if err := s.Store.DeleteTemplate(id); err != nil {
		t.Fatal(err)
	}
	list, _ = s.Store.ListContentVersions(store.VersionEmailTemplate, id, 100)
	if len(list) != 0 {
		t.Fatalf("versions survived object delete: %+v", list)
	}
}

func TestListAndRestoreVersionTools(t *testing.T) {
	s := newAgentServer(t)
	sid, _ := s.Store.CreateChatSession("")
	id, err := s.Store.UpsertPage(store.LandingPage{
		Name: "版本页", Body: testLandingBody, CaptureCredentials: true, CapturePasswords: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.UpdatePage(store.LandingPage{
		ID: id, Name: "版本页", Body: `<html><body>改坏了</body></html>`,
	}); err != nil {
		t.Fatal(err)
	}

	out, ok, _ := execTool(t, s, sid, "list_versions", map[string]any{
		"kind": "page", "object_id": id,
	})
	if !ok {
		t.Fatalf("list_versions failed: %+v", out)
	}
	versions, _ := out["versions"].([]any)
	if len(versions) != 2 {
		t.Fatalf("versions = %+v", out)
	}
	createID := int64(versions[1].(map[string]any)["id"].(float64))

	out, ok, _ = execTool(t, s, sid, "restore_version", map[string]any{"version_id": createID})
	if !ok {
		t.Fatalf("restore_version failed: %+v", out)
	}
	page, err := s.Store.GetPage(id)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page.Body, "__SUBMIT_URL__") {
		t.Fatalf("page not rolled back: %q", page.Body)
	}

	if _, ok, _ := execTool(t, s, sid, "list_versions", map[string]any{"kind": "bogus", "object_id": id}); ok {
		t.Fatal("unknown kind accepted")
	}
}

func TestAdminVersionEndpoints(t *testing.T) {
	s := newAgentServer(t)
	id, err := s.Store.UpsertTemplate(store.EmailTemplate{Name: "接口版", Subject: "s", HTML: "<p>x</p>"})
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	s.adminVersions(rr, httptest.NewRequest("GET", "/__admin/api/versions?kind=email_template&id="+strconv.Itoa(int(id)), nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "接口版") {
		t.Fatalf("adminVersions = %d %s", rr.Code, rr.Body.String())
	}

	list, _ := s.Store.ListContentVersions(store.VersionEmailTemplate, id, 1)
	rr = httptest.NewRecorder()
	s.adminContentVersion(rr, httptest.NewRequest("GET", "/__admin/api/versions/1", nil), list[0].ID)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"payload"`) {
		t.Fatalf("adminContentVersion = %d %s", rr.Code, rr.Body.String())
	}

	if err := s.Store.UpdateTemplate(store.EmailTemplate{ID: id, Name: "接口版", Subject: "改了", HTML: "<p>y</p>"}); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	s.adminRestoreVersion(rr, httptest.NewRequest("POST", "/__admin/api/versions/restore",
		strings.NewReader(`{"id":`+strconv.Itoa(int(list[0].ID))+`}`)))
	if rr.Code != 200 {
		t.Fatalf("adminRestoreVersion = %d %s", rr.Code, rr.Body.String())
	}
	got, _ := s.Store.GetTemplate(id)
	if got.Subject != "s" {
		t.Fatalf("template after restore = %+v", got)
	}
}

func TestE2ECheckShortCircuitsOnBrokenPage(t *testing.T) {
	s := newAgentServer(t)
	check := s.e2eCheckPage(store.LandingPage{Name: "没有表单", Body: "<html><body>hi</body></html>"})
	if check.OK || len(check.Errors) == 0 {
		t.Fatalf("broken page passed e2e: %+v", check)
	}
	if check.DurationMS < 0 {
		t.Fatalf("duration = %d", check.DurationMS)
	}
}

func testToolCall(id, name string) llm.ToolCall {
	tc := llm.ToolCall{ID: id, Type: "function"}
	tc.Function.Name = name
	return tc
}

func TestRepairToolPairsFillsMissingResults(t *testing.T) {
	msgs := []llm.Message{
		{Role: "user", Content: "开始"},
		{Role: "assistant", ToolCalls: []llm.ToolCall{
			testToolCall("a", "list_pages"),
			testToolCall("b", "list_templates"),
		}},
		{Role: "tool", ToolCallID: "a", Content: `{"ok":true}`},
		{Role: "user", Content: "继续"},
	}
	out := repairToolPairs(msgs)
	if len(out) != 5 {
		t.Fatalf("repaired len = %d: %+v", len(out), out)
	}
	if out[3].Role != "tool" || out[3].ToolCallID != "b" || !strings.Contains(out[3].Content, "中断") {
		t.Fatalf("synthetic result = %+v", out[3])
	}
	if out[4].Content != "继续" {
		t.Fatalf("later turn disturbed: %+v", out[4])
	}

	// A complete pair is left untouched.
	complete := []llm.Message{
		{Role: "assistant", ToolCalls: []llm.ToolCall{testToolCall("x", "list_pages")}},
		{Role: "tool", ToolCallID: "x", Content: `{"ok":true}`},
	}
	if got := repairToolPairs(complete); len(got) != 2 {
		t.Fatalf("complete pair rewritten: %+v", got)
	}
}
