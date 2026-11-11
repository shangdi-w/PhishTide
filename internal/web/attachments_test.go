package web

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"phishsim/internal/core/store"
)

func TestPayloadAttachmentUploadAndAttach(t *testing.T) {
	s := newAgentServer(t)

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "演练样本.zip")
	_, _ = fw.Write([]byte("PK\x03\x04fake-payload"))
	_ = mw.WriteField("note", "隔离样本")
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/__admin/api/attachments", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	s.adminPayloadAttachments(rr, req)
	if rr.Code != 200 {
		t.Fatalf("upload status = %d body=%s", rr.Code, rr.Body.String())
	}
	var up map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &up)
	id := int64(up["id"].(float64))

	list, err := s.Store.ListPayloadAttachments()
	if err != nil || len(list) != 1 || list[0].Name != "演练样本.zip" || list[0].Note != "隔离样本" {
		t.Fatalf("list = %+v err=%v", list, err)
	}

	tid, err := s.Store.UpsertTemplate(store.EmailTemplate{Name: "带附件模板", Subject: "s", HTML: "<p>x</p>"})
	if err != nil {
		t.Fatal(err)
	}
	attachBody := []byte(`{"template_id":` + itoa64(tid) + `}`)
	rr = httptest.NewRecorder()
	s.adminPayloadAttachmentAttach(rr, httptest.NewRequest(http.MethodPost, "/__admin/api/attachments/"+itoa64(id)+"/attach", bytes.NewReader(attachBody)), id)
	if rr.Code != 200 {
		t.Fatalf("attach status = %d body=%s", rr.Code, rr.Body.String())
	}
	atts, _ := s.Store.TemplateAttachmentsWithBody(tid)
	if len(atts) != 1 || atts[0].Name != "演练样本.zip" || !bytes.Contains(atts[0].Body, []byte("fake-payload")) {
		t.Fatalf("template attachments = %+v", atts)
	}

	// Attaching the same file twice is refused.
	rr = httptest.NewRecorder()
	s.adminPayloadAttachmentAttach(rr, httptest.NewRequest(http.MethodPost, "/__admin/api/attachments/"+itoa64(id)+"/attach", bytes.NewReader(attachBody)), id)
	if rr.Code != 400 {
		t.Fatalf("duplicate attach should fail, got %d", rr.Code)
	}
}

func TestPayloadAttachmentRejectsEmptyAndOversize(t *testing.T) {
	s := newAgentServer(t)

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "empty.bin")
	_ = fw
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/__admin/api/attachments", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	s.adminPayloadAttachments(rr, req)
	if rr.Code != 400 {
		t.Fatalf("empty upload should be rejected, got %d", rr.Code)
	}
}
