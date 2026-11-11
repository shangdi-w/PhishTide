package web

// Read-only send history endpoint. The ledger is independent of campaigns, so
// operators and the assistant can still verify delivery after a campaign was
// deleted.

import (
	"net/http"
	"strconv"
)

func (s *Server) adminSendHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, 405, map[string]any{"error": "GET only"})
		return
	}
	q := r.URL.Query().Get("query")
	cid, _ := strconv.ParseInt(r.URL.Query().Get("campaign_id"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 199 {
		limit = 100
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	entries, err := s.Store.ListSendLedgerPage(limit+1, offset, q, cid)
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	hasMore := len(entries) > limit
	if hasMore {
		entries = entries[:limit]
	}
	deleted, _ := s.Store.ListDeletedCampaigns(20)
	s.writeJSON(w, 200, map[string]any{"entries": entries, "deleted_campaigns": deleted,
		"has_more": hasMore, "offset": offset, "limit": limit})
}
