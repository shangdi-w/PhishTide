package web

// Cross-campaign suppression list API.

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (s *Server) adminSuppressions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list, err := s.Store.ListSuppressions(500)
		if err != nil {
			s.writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		s.writeJSON(w, 200, map[string]any{"suppressions": list})
	case http.MethodPost:
		var req struct {
			Email  string `json:"email"`
			Reason string `json:"reason"`
			Note   string `json:"note"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		email := strings.TrimSpace(req.Email)
		if email == "" || !strings.Contains(email, "@") {
			s.writeJSON(w, 400, map[string]any{"error": "email 无效"})
			return
		}
		if err := s.Store.UpsertSuppression(email, strings.TrimSpace(req.Reason), strings.TrimSpace(req.Note)); err != nil {
			s.writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		s.writeJSON(w, 200, map[string]any{"ok": true, "email": strings.ToLower(email)})
	default:
		s.writeJSON(w, 405, map[string]any{"error": "GET or POST"})
	}
}

func (s *Server) adminDeleteSuppression(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	ok, err := s.Store.DeleteSuppression(req.Email)
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if !ok {
		s.writeJSON(w, 404, map[string]any{"error": "不在抑制名单中"})
		return
	}
	s.writeJSON(w, 200, map[string]any{"deleted": strings.ToLower(strings.TrimSpace(req.Email))})
}

// adminBulkSuppress adds many addresses at once. Input is a list or a text
// block (newline/comma/semicolon/space separated).
func (s *Server) adminBulkSuppress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var req struct {
		Emails []string `json:"emails"`
		Text   string   `json:"text"`
		Reason string   `json:"reason"`
		Note   string   `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	emails := req.Emails
	if len(emails) == 0 && strings.TrimSpace(req.Text) != "" {
		emails = strings.FieldsFunc(req.Text, func(r rune) bool {
			return r == '\n' || r == '\r' || r == ',' || r == ';' || r == '，' || r == '；' || r == ' ' || r == '\t'
		})
	}
	added := 0
	for _, e := range emails {
		e = strings.TrimSpace(e)
		if e == "" || !strings.Contains(e, "@") {
			continue
		}
		if err := s.Store.UpsertSuppression(e, strings.TrimSpace(req.Reason), strings.TrimSpace(req.Note)); err != nil {
			s.writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		added++
	}
	s.writeJSON(w, 200, map[string]any{"added": added})
}
