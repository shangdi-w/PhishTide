package web

// Admin endpoints for content version history: list snapshots of a template or
// landing page, read one snapshot's full payload, and roll an object back to a
// snapshot. Also hosts the landing page end-to-end self-check endpoint.

import (
	"encoding/json"
	"net/http"
	"strings"

	"phishsim/internal/core/store"
)

// normalizeVersionKind accepts the stored kind or a short alias.
func normalizeVersionKind(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "email_template", "email-template", "template", "邮件模板":
		return store.VersionEmailTemplate, true
	case "landing_page", "landing-page", "page", "落地页":
		return store.VersionLandingPage, true
	}
	return "", false
}

// adminVersions lists an object's snapshots. GET ?kind=&id=&limit=
func (s *Server) adminVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	q := r.URL.Query()
	kind, ok := normalizeVersionKind(q.Get("kind"))
	if !ok {
		s.writeJSON(w, 400, map[string]any{"error": "kind 必须是 email_template 或 landing_page"})
		return
	}
	id := parseInt(q.Get("id"))
	if id <= 0 {
		s.writeJSON(w, 400, map[string]any{"error": "id 必填"})
		return
	}
	list, err := s.Store.ListContentVersions(kind, id, int(parseInt(q.Get("limit"))))
	if err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"kind": kind, "object_id": id, "versions": list})
}

// adminContentVersion returns one snapshot including its payload.
func (s *Server) adminContentVersion(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	v, err := s.Store.GetContentVersion(id)
	if err != nil {
		s.writeJSON(w, 404, map[string]any{"error": "版本不存在"})
		return
	}
	out := map[string]any{
		"id": v.ID, "kind": v.Kind, "object_id": v.ObjectID, "name": v.Name,
		"action": v.Action, "size_bytes": v.SizeBytes, "created_at": v.CreatedAt,
	}
	// Payload is json:"-" on the struct; expose it as raw JSON when possible.
	if json.Valid([]byte(v.Payload)) {
		out["payload"] = json.RawMessage(v.Payload)
	} else {
		out["payload_text"] = v.Payload
	}
	s.writeJSON(w, 200, out)
}

// adminRestoreVersion rolls an object back to a snapshot. The rollback is
// itself versioned, so it can be undone.
func (s *Server) adminRestoreVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		ID        int64 `json:"id"`
		VersionID int64 `json:"version_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json: " + err.Error()})
		return
	}
	id := req.ID
	if id <= 0 {
		id = req.VersionID
	}
	if id <= 0 {
		s.writeJSON(w, 400, map[string]any{"error": "id 必填"})
		return
	}
	v, err := s.Store.RestoreContentVersion(id)
	if err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{
		"restored": v.ID, "kind": v.Kind, "object_id": v.ObjectID, "name": v.Name,
	})
}

// adminPageE2E runs the headless browser end-to-end check for one page.
func (s *Server) adminPageE2E(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	p, err := s.Store.GetPage(id)
	if err != nil {
		s.writeJSON(w, 404, map[string]any{"error": "落地页不存在"})
		return
	}
	check := s.e2eCheckPage(p)
	s.writeJSON(w, 200, check)
}
