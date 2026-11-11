package web

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"phishsim/internal/core/config"
)

func testServer() *Server {
	return &Server{Cfg: &config.Config{
		AdminUser:      "admin",
		AdminPass:      "correct horse",
		SessionTTL:     time.Hour,
		TrustedProxies: []string{"127.0.0.1/32", "10.0.0.0/8"},
	}}
}

func TestSessionTokenRoundTrip(t *testing.T) {
	s := testServer()
	tok, err := s.newSessionToken()
	if err != nil {
		t.Fatalf("newSessionToken: %v", err)
	}
	if !s.validSessionToken(tok) {
		t.Fatal("fresh token rejected")
	}
	// Tamper with the payload.
	parts := strings.SplitN(tok, ".", 2)
	if s.validSessionToken(tamperFlip(parts[0]) + "." + parts[1]) {
		t.Fatal("tampered token accepted")
	}
	// Tamper with the signature.
	if s.validSessionToken(parts[0] + "." + tamperFlip(parts[1])) {
		t.Fatal("tampered signature accepted")
	}
	// A token signed with a different key must fail.
	other := testServer()
	other.SessionKey = []byte("01234567890123456789012345678901")
	otherTok, _ := other.newSessionToken()
	if s.validSessionToken(otherTok) {
		t.Fatal("token signed with another key accepted")
	}
}

// tamperFlip changes the first character of a base64url segment. The first
// character is always fully significant; flipping the last one can leave the
// decoded bytes unchanged because trailing characters may carry only padding
// bits, which made the old test flaky.
func tamperFlip(s string) string {
	if s == "" {
		return "x"
	}
	if s[0] == 'A' {
		return "B" + s[1:]
	}
	return "A" + s[1:]
}

func TestSessionTokenExpiry(t *testing.T) {
	s := testServer()
	s.Cfg.SessionTTL = -time.Minute
	tok, err := s.newSessionToken()
	if err != nil {
		t.Fatalf("newSessionToken: %v", err)
	}
	if s.validSessionToken(tok) {
		t.Fatal("expired token accepted")
	}
}

func TestCheckCredentials(t *testing.T) {
	s := testServer()
	if !s.checkCredentials("admin", "correct horse") {
		t.Fatal("valid plaintext credentials rejected")
	}
	if s.checkCredentials("admin", "wrong") {
		t.Fatal("wrong password accepted")
	}
	if s.checkCredentials("root", "correct horse") {
		t.Fatal("wrong username accepted")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("bcrypt-pass"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	s.Cfg.AdminPass = ""
	s.Cfg.AdminPassHash = string(hash)
	if !s.checkCredentials("admin", "bcrypt-pass") {
		t.Fatal("valid bcrypt credentials rejected")
	}
	if s.checkCredentials("admin", "correct horse") {
		t.Fatal("plaintext password accepted when a hash is configured")
	}

	// Legacy: no password, admin key doubles as the password.
	s.Cfg.AdminPassHash = ""
	s.Cfg.AdminKey = "legacy-key"
	if !s.checkCredentials("admin", "legacy-key") {
		t.Fatal("legacy admin key login rejected")
	}
}

func TestLoginLimiter(t *testing.T) {
	var l loginLimiter
	for i := 0; i < loginMaxFails-1; i++ {
		l.fail("1.2.3.4")
		if !l.allow("1.2.3.4") {
			t.Fatalf("locked after %d failures", i+1)
		}
	}
	l.fail("1.2.3.4")
	if l.allow("1.2.3.4") {
		t.Fatal("not locked after reaching the failure threshold")
	}
	if !l.allow("5.6.7.8") {
		t.Fatal("lockout leaked to another IP")
	}
	l.reset("1.2.3.4")
	if !l.allow("1.2.3.4") {
		t.Fatal("reset did not clear the lockout")
	}
}

func TestRemoteIPTrustsOnlyProxies(t *testing.T) {
	s := testServer()

	// Direct client: X-Forwarded-For must be ignored.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	if got := s.remoteIP(r); got != "203.0.113.9" {
		t.Fatalf("direct client spoofed IP: %s", got)
	}

	// Trusted proxy: honour the rightmost non-proxy address, ignoring a
	// client-supplied spoof on the left.
	r = httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.7")
	if got := s.remoteIP(r); got != "198.51.100.7" {
		t.Fatalf("proxy chain resolved to %s", got)
	}
}

func TestSameOriginAndCrossSite(t *testing.T) {
	r := httptest.NewRequest("POST", "https://phish.example.com/__admin/api/x", nil)
	r.Host = "phish.example.com"
	r.Header.Set("Origin", "https://phish.example.com")
	if !sameOrigin(r) || crossSite(r) {
		t.Fatal("same-origin request misclassified")
	}
	r.Header.Set("Origin", "https://evil.example")
	if sameOrigin(r) || !crossSite(r) {
		t.Fatal("cross-origin request misclassified")
	}
	r.Header.Set("Origin", "")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if !sameOrigin(r) || crossSite(r) {
		t.Fatal("Sec-Fetch-Site same-origin misclassified")
	}
}

func TestSanitizeCSVRow(t *testing.T) {
	row := []string{"=cmd|' /C calc'!A0", "+1", "-2", "@SUM(A1)", "normal", "", "\tlead", " =cmd"}
	sanitizeCSVRow(row)
	for i, wantQuote := range []bool{true, true, true, true, false, false, false, true} {
		got := strings.HasPrefix(row[i], "'")
		if got != wantQuote {
			t.Errorf("cell %d = %q, quoted=%v want %v", i, row[i], got, wantQuote)
		}
	}
}

func TestCappedSubmission(t *testing.T) {
	fields := map[string][]string{}
	for i := 0; i < maxCaptureFields+50; i++ {
		fields[strings.Repeat("k", i%10)+strconv.Itoa(i)] = []string{strings.Repeat("x", maxCapturedValue+10)}
	}
	out := capFields(fields)
	if len(out) > maxCaptureFields {
		t.Fatalf("field count %d exceeds cap", len(out))
	}
	for _, vs := range out {
		if len(vs[0]) > maxCapturedValue {
			t.Fatalf("value length %d exceeds cap", len(vs[0]))
		}
	}
}
