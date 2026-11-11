package web

import (
	"testing"
	"time"

	"phishsim/internal/core/store"
	"phishsim/internal/features/email"
)

func TestSendPolicyFromEnv(t *testing.T) {
	t.Setenv("PHISH_SEND_RETRY", "4")
	t.Setenv("PHISH_SEND_BREAKER", "0")
	p := sendPolicyFromEnv()
	if p.attempts != 4 || p.breaker != 0 {
		t.Fatalf("policy = %+v", p)
	}

	t.Setenv("PHISH_SEND_RETRY", "99")
	t.Setenv("PHISH_SEND_BREAKER", "-3")
	p = sendPolicyFromEnv()
	if p.attempts != 5 || p.breaker != 0 {
		t.Fatalf("clamped policy = %+v", p)
	}

	t.Setenv("PHISH_SEND_RETRY", "oops")
	t.Setenv("PHISH_SEND_BREAKER", "")
	p = sendPolicyFromEnv()
	if p.attempts != 2 || p.breaker != 5 {
		t.Fatalf("default policy = %+v", p)
	}
}

func TestRetryDelayBacksOff(t *testing.T) {
	if d := retryDelay(email.FailNetwork, 0); d != 2*time.Second {
		t.Fatalf("network attempt 0 = %v", d)
	}
	if d := retryDelay(email.FailNetwork, 1); d != 4*time.Second {
		t.Fatalf("network attempt 1 = %v", d)
	}
	if d := retryDelay(email.FailNetwork, 9); d != 30*time.Second {
		t.Fatalf("network cap = %v", d)
	}
	if d := retryDelay(email.FailThrottle, 0); d != 5*time.Second {
		t.Fatalf("throttle attempt 0 = %v", d)
	}
	if d := retryDelay(email.FailThrottle, 20); d != 60*time.Second {
		t.Fatalf("throttle cap = %v", d)
	}
}

func TestPolicyTrips(t *testing.T) {
	p := sendPolicy{attempts: 2, breaker: 3}
	if p.trips(email.Failure{Kind: email.FailHard}, 2) {
		t.Fatal("breaker tripped before threshold")
	}
	if !p.trips(email.Failure{Kind: email.FailHard}, 3) {
		t.Fatal("breaker did not trip at threshold")
	}
	if !p.trips(email.Failure{Kind: email.FailAuth, Global: true}, 1) {
		t.Fatal("global failure did not trip immediately")
	}
	off := sendPolicy{attempts: 2, breaker: 0}
	if off.trips(email.Failure{Kind: email.FailHard}, 100) {
		t.Fatal("disabled breaker tripped")
	}
}

func TestBreakerReason(t *testing.T) {
	if s := breakerReason(email.Failure{Kind: email.FailAuth, Global: true, Code: 535}, 1); s == "" {
		t.Fatal("empty global reason")
	}
	if s := breakerReason(email.Failure{Kind: email.FailHard}, 5); s == "" {
		t.Fatal("empty consecutive reason")
	}
}

func TestListSendFailuresTool(t *testing.T) {
	s := newAgentServer(t)
	if err := s.Store.RecordSendFailure(store.SendFailure{
		CampaignID: 42, ResultID: 3, Email: "a@example.com",
		Kind: "auth", Error: "535 Authentication credentials invalid", Attempts: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.RecordSendFailure(store.SendFailure{
		CampaignID: 42, ResultID: 4, Email: "b@example.com",
		Kind: "auth", Error: "535 Authentication credentials invalid", Attempts: 1,
	}); err != nil {
		t.Fatal(err)
	}
	out, ok, note := execTool(t, s, 0, "list_send_failures", map[string]any{"campaign_id": 42})
	if !ok {
		t.Fatalf("tool failed: %s", note)
	}
	if got := int(out["count"].(float64)); got != 2 {
		t.Fatalf("count = %d, out = %+v", got, out)
	}
	byKind, _ := out["by_kind"].(map[string]any)
	if int(byKind["auth"].(float64)) != 2 {
		t.Fatalf("by_kind = %+v", byKind)
	}

	out, ok, _ = execTool(t, s, 0, "list_send_failures", map[string]any{"campaign_id": 999})
	if !ok || int(out["count"].(float64)) != 0 {
		t.Fatalf("empty campaign = %+v", out)
	}
}
