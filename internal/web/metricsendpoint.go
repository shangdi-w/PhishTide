package web

// Prometheus exposition endpoint (/metrics). Access is token-based when
// PHISH_METRICS_TOKEN is set; otherwise only loopback scrapes are allowed.

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(os.Getenv("PHISH_METRICS_TOKEN"))
	if token != "" {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		q := strings.TrimSpace(r.URL.Query().Get("token"))
		okHeader := subtle.ConstantTimeCompare([]byte(auth), []byte("Bearer "+token)) == 1
		okQuery := subtle.ConstantTimeCompare([]byte(q), []byte(token)) == 1
		if !okHeader && !okQuery {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	} else if ip := net.ParseIP(s.remoteIP(r)); ip == nil || !ip.IsLoopback() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var b strings.Builder
	metric := func(name, help, typ string, value any, labels string) {
		if help != "" {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
		}
		fmt.Fprintf(&b, "%s%s %v\n", name, labels, value)
	}
	metric("phishsim_up", "Platform is running", "gauge", 1, "")
	metric("phishsim_uptime_seconds", "Process uptime", "gauge", int64(time.Since(appStartedAt).Seconds()), "")
	metric("phishsim_goroutines", "Goroutines", "gauge", runtime.NumGoroutine(), "")
	if s.Store != nil {
		if err := s.Store.Ping(); err == nil {
			metric("phishsim_db_up", "Database reachable", "gauge", 1, "")
		} else {
			metric("phishsim_db_up", "Database reachable", "gauge", 0, "")
		}
		stats := s.Store.DBStats()
		metric("phishsim_db_open_connections", "Open DB connections", "gauge", stats.OpenConnections, "")
		metric("phishsim_db_in_use", "DB connections in use", "gauge", stats.InUse, "")
		counts := s.Store.TableCounts()
		for _, table := range []string{"campaigns", "targets", "submissions", "email_templates", "landing_pages", "send_ledger", "agent_runs"} {
			if n, ok := counts[table]; ok && n >= 0 {
				metric("phishsim_table_rows", "Rows per table", "gauge", n, `{table="`+table+`"}`)
			}
		}
		for status, n := range s.Store.SendJobStatusCounts() {
			metric("phishsim_send_jobs", "Scheduled send jobs by status", "gauge", n, `{status="`+status+`"}`)
		}
		if m, err := s.Store.AgentMetricsTotals(); err == nil {
			metric("phishsim_agent_runs_total", "Agent runs", "counter", m.Runs, "")
			metric("phishsim_agent_tool_calls_total", "Agent tool calls", "counter", m.ToolCalls, "")
			metric("phishsim_agent_tool_errors_total", "Agent tool errors", "counter", m.ToolErrors, "")
			metric("phishsim_agent_tokens_total", "Agent tokens", "counter", m.TotalTokens, "")
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
