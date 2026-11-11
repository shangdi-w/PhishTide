package email

// Delivery failure classification. A campaign send needs more than a failed
// counter: the operator has to know whether a recipient is permanently invalid
// (stop retrying), the relay is throttling (back off), or the credentials /
// certificate / DNS are wrong (every remaining recipient will fail the same
// way, so the sender must stop instead of burning the domain's reputation).

import (
	"context"
	"errors"
	"io"
	"net"
	"net/textproto"
	"strings"
)

// FailKind is a coarse, operator-facing bucket for an SMTP failure.
type FailKind string

const (
	FailHard     FailKind = "hard"     // 5xx: mailbox/recipient permanently rejected
	FailSoft     FailKind = "soft"     // 4xx: transient, retry later
	FailThrottle FailKind = "throttle" // rate limit / too many connections
	FailAuth     FailKind = "auth"     // credentials rejected
	FailTLS      FailKind = "tls"      // certificate/handshake problem
	FailDNS      FailKind = "dns"      // host does not resolve
	FailNetwork  FailKind = "network"  // connection reset/timeout/EOF
	FailBuild    FailKind = "build"    // message could not be constructed
	FailRender   FailKind = "render"   // template rendering failed
	FailUnknown  FailKind = "unknown"
)

// Failure is one classified delivery error.
type Failure struct {
	Kind      FailKind `json:"kind"`
	Code      int      `json:"code,omitempty"`
	Retryable bool     `json:"retryable"`
	// Global failures are configuration/environment problems that will hit
	// every remaining recipient (auth, TLS, DNS, message build). They trip the
	// circuit breaker immediately.
	Global  bool   `json:"global"`
	Message string `json:"message"`
}

// Classify maps an SMTP error to a Failure. It never returns a nil error for a
// non-nil input.
func Classify(err error) Failure {
	if err == nil {
		return Failure{}
	}
	msg := strings.TrimSpace(err.Error())
	low := strings.ToLower(msg)
	f := Failure{Message: msg}

	var tp *textproto.Error
	if errors.As(err, &tp) {
		f.Code = tp.Code
		switch {
		case tp.Code == 530 || tp.Code == 534 || tp.Code == 535 || tp.Code == 538:
			f.Kind, f.Global = FailAuth, true
		case tp.Code == 552:
			// "storage exceeded" / mailbox full is often cleared later.
			f.Kind, f.Retryable = FailSoft, true
		case tp.Code >= 500:
			f.Kind = FailHard
		case tp.Code >= 400:
			serverMsg := strings.ToLower(tp.Msg)
			// 452 is "too many recipients" — a per-message problem, not relay
			// throttling, so it stays soft. "too many connections" is throttling.
			if tp.Code == 451 || tp.Code == 421 || strings.Contains(serverMsg, "too many connections") ||
				strings.Contains(serverMsg, "rate") || strings.Contains(serverMsg, "limit") ||
				strings.Contains(serverMsg, "throttl") || strings.Contains(serverMsg, "try again later") {
				f.Kind = FailThrottle
			} else {
				f.Kind = FailSoft
			}
			f.Retryable = true
		default:
			f.Kind = FailUnknown
		}
		return f
	}

	switch {
	case strings.Contains(low, "x509:") || strings.Contains(low, "tls:") ||
		strings.Contains(low, "certificate") || strings.Contains(low, "handshake"):
		f.Kind, f.Global = FailTLS, true
		return f
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) || strings.Contains(low, "no such host") {
		f.Kind, f.Global = FailDNS, true
		return f
	}

	if strings.Contains(low, "authentication") || strings.Contains(low, "auth failed") ||
		strings.Contains(low, "username and password not accepted") ||
		strings.Contains(low, "invalid credentials") {
		f.Kind, f.Global = FailAuth, true
		return f
	}

	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		strings.Contains(low, "unexpected eof") || low == "eof" ||
		strings.Contains(low, "connection refused") || strings.Contains(low, "connection reset") ||
		// Windows wraps a refused connect as "No connection could be made
		// because the target machine actively refused it."
		strings.Contains(low, "actively refused") || strings.Contains(low, "no connection could be made") ||
		strings.Contains(low, "broken pipe") || strings.Contains(low, "i/o timeout") ||
		strings.Contains(low, "use of closed network connection") {
		f.Kind, f.Retryable = FailNetwork, true
		return f
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		f.Kind = FailNetwork
		f.Retryable = netErr.Timeout()
		return f
	}

	if strings.Contains(low, "smtp host required") || strings.Contains(low, "refusing to send") ||
		strings.Contains(low, "invalid recipient") {
		f.Kind, f.Global = FailBuild, true
		return f
	}

	f.Kind = FailUnknown
	return f
}
