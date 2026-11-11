package web

// Isolated payload attachment library. The console may upload arbitrary files
// for use as email attachments; the platform never executes, extracts or
// previews them, and there is no endpoint that returns the raw bytes to the
// browser. Files are sealed at rest and only read by the SMTP sender.

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"phishsim/internal/core/store"
)

// maxPayloadBytes bounds one library upload. Larger files are rejected rather
// than buffered.
const maxPayloadBytes = 20 << 20

// adminPayloadAttachments lists metadata or accepts a multipart upload.
func (s *Server) adminPayloadAttachments(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list, err := s.Store.ListPayloadAttachments()
		if err != nil {
			s.writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		s.writeJSON(w, 200, map[string]any{"attachments": list})
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxPayloadBytes+(1<<20))
		if err := r.ParseMultipartForm(maxPayloadBytes + (1 << 20)); err != nil {
			s.writeJSON(w, 400, map[string]any{"error": "附件解析失败（单文件不超过 20MB）"})
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			s.writeJSON(w, 400, map[string]any{"error": "缺少 file 字段"})
			return
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, maxPayloadBytes+1))
		if err != nil {
			s.writeJSON(w, 400, map[string]any{"error": "读取文件失败"})
			return
		}
		if len(data) == 0 {
			s.writeJSON(w, 400, map[string]any{"error": "文件为空"})
			return
		}
		if len(data) > maxPayloadBytes {
			s.writeJSON(w, 400, map[string]any{"error": "文件超过 20MB"})
			return
		}
		name := filepath.Base(strings.TrimSpace(header.Filename))
		if name == "" || name == "." || name == string(filepath.Separator) {
			s.writeJSON(w, 400, map[string]any{"error": "文件名无效"})
			return
		}
		if utf8.RuneCountInString(name) > 255 {
			name = string([]rune(name)[:255])
		}
		ct := header.Header.Get("Content-Type")
		if ct == "" {
			ct = mime.TypeByExtension(filepath.Ext(name))
		}
		if ct == "" {
			ct = "application/octet-stream"
		}
		note := strings.TrimSpace(r.FormValue("note"))
		if utf8.RuneCountInString(note) > 500 {
			note = string([]rune(note)[:500])
		}
		a := store.PayloadAttachment{Name: name, ContentType: ct, Note: note}
		id, err := s.Store.AddPayloadAttachment(a, data)
		if err != nil {
			s.writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		s.log().Info("payload attachment stored", "id", id, "name", name, "bytes", len(data), "ip", s.remoteIP(r))
		s.writeJSON(w, 200, map[string]any{"id": id, "name": name, "size_bytes": len(data)})
	default:
		s.writeJSON(w, 405, map[string]any{"error": "GET or POST"})
	}
}

// adminPayloadAttachmentDelete removes one library entry.
func (s *Server) adminPayloadAttachmentDelete(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodDelete {
		s.writeJSON(w, 405, map[string]any{"error": "DELETE only"})
		return
	}
	if err := s.Store.DeletePayloadAttachment(id); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"deleted": id})
}

// attachPayloadToTemplate copies one library file into a template's attachment
// list. This is the only path by which the bytes leave the isolated store.
func (s *Server) attachPayloadToTemplate(payloadID, templateID int64) (string, error) {
	if templateID <= 0 {
		return "", fmt.Errorf("请选择邮件模板")
	}
	if _, err := s.Store.GetTemplate(templateID); err != nil {
		return "", fmt.Errorf("模板不存在")
	}
	a, body, err := s.Store.GetPayloadAttachment(payloadID)
	if err != nil {
		return "", fmt.Errorf("附件不存在")
	}
	existing, _ := s.Store.ListTemplateAttachments(templateID)
	if len(existing) >= maxAttachments {
		return "", fmt.Errorf("每个模板最多 %d 个附件", maxAttachments)
	}
	for _, e := range existing {
		if e.Name == a.Name {
			return "", fmt.Errorf("模板已有同名附件「%s」", a.Name)
		}
	}
	_, err = s.Store.AddTemplateAttachment(store.TemplateAttachment{
		TemplateID: templateID, Name: a.Name, ContentType: a.ContentType,
		Size: int64(len(body)), Body: body,
	})
	if err != nil {
		return "", err
	}
	return a.Name, nil
}

// adminPayloadAttachmentAttach mounts a library file onto a template.
func (s *Server) adminPayloadAttachmentAttach(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var req struct {
		TemplateID int64 `json:"template_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	name, err := s.attachPayloadToTemplate(id, req.TemplateID)
	if err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"ok": true, "name": name, "template_id": req.TemplateID})
}
