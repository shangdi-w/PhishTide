package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAdminLogsReturnsEntries(t *testing.T) {
	s := newSettingsTestServer(t)
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := s.Store.InsertLog(ts, "ERROR", "clone failed", `{"url":"https://x.example","err":"timeout"}`); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.InsertLog(ts, "INFO", "platform started", `{}`); err != nil {
		t.Fatal(err)
	}

	get := func(q string) map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/__admin/api/logs"+q, nil)
		req.Header.Set("Authorization", "Bearer test-key")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	out := get("?limit=20")
	logs, _ := out["logs"].([]any)
	if len(logs) != 2 || out["errors"].(float64) != 1 {
		t.Fatalf("want 2 logs and 1 error, got %+v", out)
	}
	first, _ := logs[0].(map[string]any)
	if first["msg"] != "platform started" {
		t.Fatalf("newest log first expected, got %+v", first)
	}

	out = get("?level=error")
	if logs, _ := out["logs"].([]any); len(logs) != 1 {
		t.Fatalf("level filter failed: %+v", out)
	}

	// Clearing wipes persisted logs.
	req := httptest.NewRequest(http.MethodPost, "/__admin/api/logs/clear", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body.String())
	}
	if out := get(""); len(out["logs"].([]any)) != 0 {
		t.Fatalf("logs not cleared: %+v", out)
	}
}

func TestLogRetentionSetting(t *testing.T) {
	s := newSettingsTestServer(t)
	old := time.Now().AddDate(0, 0, -10).UTC().Format(time.RFC3339)
	recent := time.Now().UTC().Format(time.RFC3339)
	_ = s.Store.InsertLog(old, "INFO", "old log", `{}`)
	_ = s.Store.InsertLog(recent, "INFO", "new log", `{}`)

	req := httptest.NewRequest(http.MethodPost, "/__admin/api/logs/retention", stringsReader(`{"days":3}`))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("retention: %d %s", rec.Code, rec.Body.String())
	}
	if got := s.appSettingsSnapshot().LogRetentionDays; got != 3 {
		t.Fatalf("retention not saved: %d", got)
	}
	rows, _ := s.Store.LogsSince("", "", 10)
	if len(rows) != 1 || rows[0].Message != "new log" {
		t.Fatalf("old log should be pruned: %+v", rows)
	}
}

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }
