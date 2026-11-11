package web

// Delivery policy for campaign sends: per-recipient retries for transient SMTP
// errors, and a circuit breaker that stops the batch when the relay is
// rejecting everything (bad credentials, certificate, DNS) or too many
// recipients fail in a row. Without the breaker a misconfigured sender keeps
// hammering the provider and damages the sending domain's reputation.

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"phishsim/internal/core/store"
	"phishsim/internal/features/email"
)

type sendPolicy struct {
	attempts int // retries per recipient (0 = single attempt)
	breaker  int // consecutive non-global failures before stopping (0 = off)
}

func sendPolicyFromEnv() sendPolicy {
	p := sendPolicy{attempts: 2, breaker: 5}
	if n, ok := envInt("PHISH_SEND_RETRY"); ok {
		if n < 0 {
			n = 0
		}
		if n > 5 {
			n = 5
		}
		p.attempts = n
	}
	if n, ok := envInt("PHISH_SEND_BREAKER"); ok {
		if n < 0 {
			n = 0
		}
		p.breaker = n
	}
	return p
}

func envInt(key string) (int, bool) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, false
	}
	return n, true
}

// retryDelay backs off longer for throttling than for a dropped connection.
func retryDelay(kind email.FailKind, attempt int) time.Duration {
	if kind == email.FailThrottle {
		d := time.Duration(5*(attempt+1)) * time.Second
		if d > 60*time.Second {
			d = 60 * time.Second
		}
		return d
	}
	d := time.Duration(2*(1<<attempt)) * time.Second
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

// trips reports whether the breaker should stop the remaining recipients.
func (p sendPolicy) trips(f email.Failure, consecutive int) bool {
	if f.Global {
		return true
	}
	return p.breaker > 0 && consecutive >= p.breaker
}

// deliver sends one message, retrying only transient failures. A successful
// send returns the zero Failure.
func (s *Server) deliver(p sendPolicy, cfg email.SMTPConfig, msg []byte, to string) (email.Failure, int) {
	var f email.Failure
	attempts := 0
	for i := 0; i <= p.attempts; i++ {
		attempts++
		err := email.Send(cfg, msg, to)
		if err == nil {
			return email.Failure{}, attempts
		}
		f = email.Classify(err)
		if !f.Retryable || i == p.attempts {
			break
		}
		time.Sleep(retryDelay(f.Kind, i))
	}
	return f, attempts
}

func breakerReason(f email.Failure, consecutive int) string {
	if f.Global {
		if f.Code > 0 {
			return fmt.Sprintf("全局错误 %s (SMTP %d)，后续收件人也会失败，已停止发送", f.Kind, f.Code)
		}
		return fmt.Sprintf("全局错误 %s，后续收件人也会失败，已停止发送", f.Kind)
	}
	return fmt.Sprintf("连续 %d 个收件人发送失败（%s），已暂停后续发送", consecutive, f.Kind)
}

// adminSendFailures lists the latest delivery failure of each recipient.
func (s *Server) adminSendFailures(w http.ResponseWriter, r *http.Request, campaignID int64) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	rows, err := s.Store.ListSendFailures(campaignID, limit)
	if err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"failures": rows, "count": len(rows)})
}

// recordSendFailure persists one failure; resultID is 0 for seed addresses.
func (s *Server) recordSendFailure(campaignID, resultID int64, to, kind, text string, attempts int) {
	if s.Store == nil {
		return
	}
	_ = s.Store.RecordSendFailure(store.SendFailure{
		CampaignID: campaignID, ResultID: resultID, Email: to,
		Kind: kind, Error: text, Attempts: attempts,
	})
}
