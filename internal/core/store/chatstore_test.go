package store

import (
	"path/filepath"
	"testing"
)

func openChatTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "chat.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestTemplateAttachmentsRoundTrip(t *testing.T) {
	s := openChatTestStore(t)
	tid, err := s.UpsertTemplate(EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.AddTemplateAttachment(TemplateAttachment{
		TemplateID: tid, Name: "报表.pdf", ContentType: "application/pdf", Body: []byte("%PDF-1.4"),
	})
	if err != nil {
		t.Fatal(err)
	}
	meta, err := s.ListTemplateAttachments(tid)
	if err != nil || len(meta) != 1 || meta[0].Name != "报表.pdf" || meta[0].Size != 8 {
		t.Fatalf("meta = %+v, err = %v", meta, err)
	}
	if len(meta[0].Body) != 0 {
		t.Fatal("metadata list should not load bodies")
	}
	full, err := s.TemplateAttachmentsWithBody(tid)
	if err != nil || len(full) != 1 || string(full[0].Body) != "%PDF-1.4" {
		t.Fatalf("full = %+v, err = %v", full, err)
	}
}

func TestUpsertTemplateByNameReturnsStableID(t *testing.T) {
	s := openChatTestStore(t)
	id1, err := s.UpsertTemplate(EmailTemplate{Name: "同名模板", Subject: "a", HTML: "<p>1</p>"})
	if err != nil {
		t.Fatal(err)
	}
	id2, err := s.UpsertTemplate(EmailTemplate{Name: "同名模板", Subject: "b", HTML: "<p>2</p>"})
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 || id1 == 0 {
		t.Fatalf("upsert ids = %d, %d", id1, id2)
	}
	if list, _ := s.ListTemplates(); len(list) != 1 || list[0].Subject != "b" {
		t.Fatalf("templates = %+v", list)
	}
}

func TestDeleteTemplateRemovesAttachments(t *testing.T) {
	s := openChatTestStore(t)
	tid, err := s.UpsertTemplate(EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddTemplateAttachment(TemplateAttachment{TemplateID: tid, Name: "a.pdf", ContentType: "application/pdf", Body: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteTemplate(tid); err != nil {
		t.Fatal(err)
	}
	atts, err := s.ListTemplateAttachments(tid)
	if err != nil || len(atts) != 0 {
		t.Fatalf("attachments survived template delete: %+v, err = %v", atts, err)
	}
	if _, err := s.GetTemplate(tid); err == nil {
		t.Fatal("template survived delete")
	}
}

func TestUpdateTemplateAndPageInPlace(t *testing.T) {
	s := openChatTestStore(t)
	tid, err := s.UpsertTemplate(EmailTemplate{Name: "old", Subject: "s", HTML: "<p>old</p>"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateTemplate(EmailTemplate{ID: tid, Name: "new", Subject: "s2", HTML: "<p>new</p>"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetTemplate(tid)
	if err != nil || got.Name != "new" || got.HTML != "<p>new</p>" {
		t.Fatalf("template = %+v, err = %v", got, err)
	}
	if list, _ := s.ListTemplates(); len(list) != 1 {
		t.Fatalf("update created a duplicate template (count %d)", len(list))
	}

	pid, err := s.UpsertPage(LandingPage{Name: "p", Kind: "template", Body: "<p>a</p>", ContentType: "text/html"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdatePage(LandingPage{ID: pid, Name: "p2", Body: "<p>b</p>", CaptureCredentials: true, CapturePasswords: true, RedirectURL: "https://example.com"}); err != nil {
		t.Fatal(err)
	}
	p, err := s.GetPage(pid)
	if err != nil || p.Body != "<p>b</p>" || !p.CapturePasswords || p.RedirectURL != "https://example.com" {
		t.Fatalf("page = %+v, err = %v", p, err)
	}
}

func TestChatSessionsMessagesAndUploads(t *testing.T) {
	s := openChatTestStore(t)
	sid, err := s.CreateChatSession("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendChatMessage(sid, "user", "你好", `{"role":"user","content":"你好"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendChatMessage(sid, "tool", "🔧 调用 list_groups", `{"role":"tool"}`); err != nil {
		t.Fatal(err)
	}
	msgs, err := s.ListChatMessages(sid)
	if err != nil || len(msgs) != 2 || msgs[0].Role != "user" || msgs[1].Content == "" {
		t.Fatalf("messages = %+v, err = %v", msgs, err)
	}
	sess, err := s.GetChatSession(sid)
	if err != nil || sess.Messages != 2 {
		t.Fatalf("session = %+v, err = %v", sess, err)
	}
	if err := s.RenameChatSession(sid, "名单导入"); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListChatSessions(10)
	if err != nil || len(list) != 1 || list[0].Title != "名单导入" {
		t.Fatalf("list = %+v, err = %v", list, err)
	}

	uid, err := s.AddChatUpload(ChatUpload{SessionID: sid, Name: "名单.csv", ContentType: "text/csv", Body: []byte("email\na@b.co\n")})
	if err != nil {
		t.Fatal(err)
	}
	up, err := s.GetChatUpload(uid)
	if err != nil || up.Name != "名单.csv" || len(up.Body) == 0 {
		t.Fatalf("upload = %+v, err = %v", up, err)
	}
	ups, err := s.ListChatUploads(sid)
	if err != nil || len(ups) != 1 || ups[0].Size != int64(len("email\na@b.co\n")) {
		t.Fatalf("uploads = %+v, err = %v", ups, err)
	}

	if err := s.DeleteChatSession(sid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetChatSession(sid); err == nil {
		t.Fatal("session survived delete")
	}
	msgs, _ = s.ListChatMessages(sid)
	if len(msgs) != 0 {
		t.Fatal("messages survived session delete")
	}
	ups, _ = s.ListChatUploads(sid)
	if len(ups) != 0 {
		t.Fatal("uploads survived session delete")
	}
}
