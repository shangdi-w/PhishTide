package email

import (
	"errors"
	"net"
	"net/textproto"
	"testing"
)

func TestClassifySMTPCodes(t *testing.T) {
	cases := []struct {
		name      string
		err       *textproto.Error
		kind      FailKind
		retryable bool
		global    bool
	}{
		{"auth 535", &textproto.Error{Code: 535, Msg: "Authentication credentials invalid"}, FailAuth, false, true},
		{"auth 534", &textproto.Error{Code: 534, Msg: "Application-specific password required"}, FailAuth, false, true},
		{"hard 550", &textproto.Error{Code: 550, Msg: "No such user"}, FailHard, false, false},
		{"soft 452", &textproto.Error{Code: 452, Msg: "Too many recipients"}, FailSoft, true, false},
		{"throttle 421", &textproto.Error{Code: 421, Msg: "Too many connections from your IP"}, FailThrottle, true, false},
		{"throttle 451", &textproto.Error{Code: 451, Msg: "Try again later"}, FailThrottle, true, false},
		{"soft 450", &textproto.Error{Code: 450, Msg: "Mailbox busy"}, FailSoft, true, false},
		{"mailbox full 552", &textproto.Error{Code: 552, Msg: "Storage exceeded"}, FailSoft, true, false},
	}
	for _, c := range cases {
		f := Classify(c.err)
		if f.Kind != c.kind || f.Retryable != c.retryable || f.Global != c.global {
			t.Errorf("%s: got %+v, want kind=%s retryable=%v global=%v",
				c.name, f, c.kind, c.retryable, c.global)
		}
		if f.Code != c.err.Code {
			t.Errorf("%s: code = %d, want %d", c.name, f.Code, c.err.Code)
		}
	}
}

func TestClassifyTransportErrors(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		kind      FailKind
		retryable bool
		global    bool
	}{
		{"dns", &net.DNSError{Err: "no such host", Name: "smtp.invalid"}, FailDNS, false, true},
		{"tls text", errors.New("x509: certificate signed by unknown authority"), FailTLS, false, true},
		{"refused", errors.New("dial tcp 127.0.0.1:25: connect: connection refused"), FailNetwork, true, false},
		{"refused windows", errors.New("dial tcp 127.0.0.1:1: connectex: No connection could be made because the target machine actively refused it."), FailNetwork, true, false},
		{"eof", errors.New("unexpected EOF"), FailNetwork, true, false},
		{"timeout", errors.New("i/o timeout"), FailNetwork, true, false},
		{"empty host", errors.New("SMTP host required"), FailBuild, false, true},
		{"header injection", errors.New("invalid recipient: header injection characters"), FailBuild, false, true},
	}
	for _, c := range cases {
		f := Classify(c.err)
		if f.Kind != c.kind || f.Retryable != c.retryable || f.Global != c.global {
			t.Errorf("%s: got %+v, want kind=%s retryable=%v global=%v",
				c.name, f, c.kind, c.retryable, c.global)
		}
		if f.Message == "" {
			t.Errorf("%s: empty message", c.name)
		}
	}
}
