package web

// Optional outbound alerts (webhook) for operational failures such as a send
// circuit breaker trip or a background job permanently failing.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"
)

// notifyAlert POSTs a JSON event to PHISH_ALERT_WEBHOOK when configured. It is
// fire-and-forget so a slow endpoint never blocks sending.
func (s *Server) notifyAlert(event string, fields map[string]any) {
	url := strings.TrimSpace(os.Getenv("PHISH_ALERT_WEBHOOK"))
	if url == "" || s == nil {
		return
	}
	payload := map[string]any{
		"event":    event,
		"platform": "phishsim",
		"time":     time.Now().UTC().Format(time.RFC3339),
	}
	for k, v := range fields {
		payload[k] = v
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	go func() {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			if s.Log != nil {
				s.Log.Warn("alert webhook failed", "event", event, "err", err)
			}
			return
		}
		resp.Body.Close()
	}()
}
