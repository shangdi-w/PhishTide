package web

// Read-only operational diagnostics exposed to the console assistant so it can
// answer "why did sending fail / is the platform healthy" without guessing.

import (
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

// appStartedAt approximates process start; used for the uptime readout.
var appStartedAt = time.Now()

// healthSnapshot collects connection, data-volume and subsystem status.
func (s *Server) healthSnapshot() map[string]any {
	out := map[string]any{
		"time":           time.Now().Format(time.RFC3339),
		"uptime_seconds": int64(time.Since(appStartedAt).Seconds()),
		"pid":            os.Getpid(),
		"go":             runtime.Version(),
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		out["version"] = bi.Main.Version
	}
	out["geo_loaded"] = s.Geo != nil
	if cli := s.getLLM(); cli != nil {
		out["llm_configured"] = cli.Available()
		out["llm_model"] = cli.Model
		out["llm_base_url"] = cli.BaseURL
	} else {
		out["llm_configured"] = false
	}
	if s.Store == nil {
		out["db_ok"] = false
		return out
	}
	if err := s.Store.Ping(); err != nil {
		out["db_ok"] = false
		out["db_error"] = err.Error()
		return out
	}
	stats := s.Store.DBStats()
	out["db_ok"] = true
	out["db_open_connections"] = stats.OpenConnections
	out["db_in_use"] = stats.InUse
	out["db_wait_count"] = stats.WaitCount
	out["tables"] = s.Store.TableCounts()
	out["send_jobs"] = s.Store.SendJobStatusCounts()
	return out
}

// readLogs returns recent log entries, filtered by minimum level and an
// optional substring, with credential-looking values masked.
func (s *Server) readLogs(level string, limit int, contains string) map[string]any {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "info", "warn", "warning", "error":
	default:
		level = ""
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	needle := strings.ToLower(strings.TrimSpace(contains))
	if s.LogBuffer == nil {
		return map[string]any{"count": 0, "entries": []map[string]any{}}
	}
	entries := s.LogBuffer.Entries(level, 0)
	out := make([]map[string]any, 0, limit)
	for _, e := range entries {
		msg := redactSecrets(e.Message)
		if needle != "" && !strings.Contains(strings.ToLower(msg), needle) {
			match := false
			for k, v := range e.Attrs {
				if strings.Contains(strings.ToLower(k), needle) || strings.Contains(strings.ToLower(v), needle) {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		attrs := make(map[string]string, len(e.Attrs))
		for k, v := range e.Attrs {
			attrs[k] = redactSecrets(v)
		}
		out = append(out, map[string]any{"time": e.Time, "level": e.Level, "msg": msg, "attrs": attrs})
		if len(out) >= limit {
			break
		}
	}
	return map[string]any{"count": len(out), "entries": out}
}
