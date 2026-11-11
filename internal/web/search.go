package web

// Cross-module search endpoint used by the console search page and the agent.

import (
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) adminSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, 405, map[string]any{"error": "GET only"})
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		s.writeJSON(w, 400, map[string]any{"error": "q required"})
		return
	}
	per, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	hits, err := s.Store.GlobalSearch(q, per)
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	for i := range hits {
		hits[i].Title = truncateRunes(redactSecrets(hits[i].Title), 120)
		hits[i].Snippet = truncateRunes(redactSecrets(hits[i].Snippet), 300)
	}
	s.writeJSON(w, 200, map[string]any{"query": q, "count": len(hits), "hits": hits})
}
