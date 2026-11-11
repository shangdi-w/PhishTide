package web

// Read-only agent telemetry for the console: per-session tokens, rounds, tool
// calls/errors and the last run's duration.

import (
	"net/http"
	"strconv"

	"phishsim/internal/core/store"
)

func (s *Server) adminAgentMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, 405, map[string]any{"error": "GET only"})
		return
	}
	sid, _ := strconv.ParseInt(r.URL.Query().Get("session_id"), 10, 64)
	if sid <= 0 {
		s.writeJSON(w, 400, map[string]any{"error": "session_id required"})
		return
	}
	m, err := s.Store.GetAgentMetrics(sid)
	if err != nil {
		m = store.AgentMetrics{SessionID: sid}
	}
	runs, _ := s.Store.GetAgentRuns(sid, 50)
	s.writeJSON(w, 200, map[string]any{"metrics": m, "runs": runs})
}

func (s *Server) adminAgentGlobalMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, 405, map[string]any{"error": "GET only"})
		return
	}
	totals, err := s.Store.AgentMetricsTotals()
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	sessions, _ := s.Store.ListAgentSessionMetrics(50)
	s.writeJSON(w, 200, map[string]any{"totals": totals, "sessions": sessions})
}
