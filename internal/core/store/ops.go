package store

import "database/sql"

// Ops helpers used by the console's read-only diagnostics tools.

// Ping verifies the database connection is usable.
func (s *Store) Ping() error { return s.db.Ping() }

// DBStats exposes pool statistics for the health endpoint.
func (s *Store) DBStats() sql.DBStats { return s.db.Stats() }

// countTables is a fixed whitelist; table names are never taken from input.
var countTables = []string{
	"campaigns", "campaign_groups", "target_groups", "targets", "results",
	"events", "submissions", "email_templates", "landing_pages",
	"sending_profiles", "send_jobs", "send_failures", "bounces",
	"chat_sessions", "chat_messages", "chat_uploads", "agent_memories",
	"agent_todos", "agent_jobs", "content_versions", "llm_usage",
}

// TableCounts returns row counts for every known table. Missing tables (older
// databases created before a migration) are reported as -1 instead of failing
// the whole call.
func (s *Store) TableCounts() map[string]int64 {
	out := make(map[string]int64, len(countTables))
	for _, t := range countTables {
		var n int64
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + t).Scan(&n); err != nil {
			out[t] = -1
			continue
		}
		out[t] = n
	}
	return out
}

// SendJobStatusCounts groups scheduled send jobs by status.
func (s *Store) SendJobStatusCounts() map[string]int64 {
	out := map[string]int64{}
	rows, err := s.db.Query(`SELECT status, COUNT(*) FROM send_jobs GROUP BY status`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var n int64
		if rows.Scan(&status, &n) == nil {
			out[status] = n
		}
	}
	return out
}
