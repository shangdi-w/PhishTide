package hygiene

import (
	"testing"

	"phishsim/internal/core/store"
)

func TestAuditFlagsCommonListProblems(t *testing.T) {
	targets := []store.Target{
		{Email: "alice@example.com"},
		{Email: "ALICE@example.com"},
		{Email: "info@example.com"},
		{Email: "bob@mailinator.com"},
		{Email: "not-an-email"},
		{Email: "carol@example.com"},
	}
	rep := Audit(targets, false, 0)
	if rep.Total != 6 || rep.Unique != 4 {
		t.Fatalf("total/unique = %d/%d, want 6/4", rep.Total, rep.Unique)
	}
	if rep.Counts[KindDuplicate] != 1 {
		t.Fatalf("duplicate count = %d", rep.Counts[KindDuplicate])
	}
	if rep.Counts[KindRole] != 1 {
		t.Fatalf("role count = %d", rep.Counts[KindRole])
	}
	if rep.Counts[KindDisposable] != 1 {
		t.Fatalf("disposable count = %d", rep.Counts[KindDisposable])
	}
	if rep.Counts[KindInvalid] != 1 {
		t.Fatalf("invalid count = %d", rep.Counts[KindInvalid])
	}
}

func TestAuditWithoutMXSkipsDNS(t *testing.T) {
	rep := Audit([]store.Target{{Email: "a@example.com"}}, false, 0)
	if len(rep.Domains) != 0 {
		t.Fatalf("domains should be empty when checkMX=false: %+v", rep.Domains)
	}
	if rep.Counts[KindNoMX] != 0 || rep.Counts[KindMXError] != 0 {
		t.Fatalf("unexpected MX issues: %+v", rep.Counts)
	}
}

func TestValidEmail(t *testing.T) {
	ok := []string{"a@example.com", "first.last@sub.example.co", "user+tag@example.cn"}
	bad := []string{"", "no-at", "@example.com", "a@", "a@localhost", "a b@example.com", "a@@example.com"}
	for _, s := range ok {
		if !validEmail(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range bad {
		if validEmail(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}
