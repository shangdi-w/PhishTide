package email

import (
	"strings"
	"testing"
)

func TestBuildRejectsRecipientHeaderInjection(t *testing.T) {
	_, err := Build(Message{
		From:    "it@example.com",
		To:      "victim@example.com\r\nBcc: attacker@example.com",
		Subject: "hello",
		HTML:    "<p>x</p>",
	})
	if err == nil {
		t.Fatal("recipient containing CRLF was accepted")
	}
}

func TestBuildStripsSubjectHeaderInjection(t *testing.T) {
	msg, err := Build(Message{
		From:    "it@example.com",
		To:      "victim@example.com",
		Subject: "hello\r\nBcc: attacker@example.com",
		HTML:    "<p>x</p>",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	raw := string(msg)
	if strings.Contains(raw, "\r\nBcc:") {
		t.Fatal("injected Bcc header survived sanitisation")
	}
	if !strings.Contains(raw, "Subject: hello") {
		t.Fatalf("subject missing from message:\n%s", raw)
	}
}

func TestSendRefusesPlaintextAuthToRemoteHost(t *testing.T) {
	err := Send(SMTPConfig{
		Host: "smtp.example.com", Port: 25, User: "u", Pass: "p", TLSMode: "none",
	}, []byte("x"), "victim@example.com")
	if err == nil || !strings.Contains(err.Error(), "plaintext") {
		t.Fatalf("plaintext auth to a remote host was not refused: %v", err)
	}
}

func TestBuildWithAttachmentsUsesMultipartMixed(t *testing.T) {
	msg, err := Build(Message{
		From:    "it@example.com",
		To:      "victim@example.com",
		Subject: "季度报表",
		HTML:    "<p>请查收附件</p>",
		Text:    "请查收附件",
		Attachments: []Attachment{
			{Name: "报表.pdf", ContentType: "application/pdf", Body: []byte("%PDF-1.4 test")},
			{Name: "note.txt", ContentType: "text/plain", Body: []byte("hello")},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	raw := string(msg)
	if !strings.Contains(raw, "multipart/mixed") {
		t.Fatalf("expected multipart/mixed:\n%s", raw)
	}
	if !strings.Contains(raw, "multipart/alternative") {
		t.Fatal("HTML body should stay in a multipart/alternative part")
	}
	if !strings.Contains(raw, "Content-Disposition: attachment") {
		t.Fatal("attachment disposition missing")
	}
	if !strings.Contains(raw, "filename*=UTF-8''") {
		t.Fatal("non-ASCII filename should use RFC 5987 filename*")
	}
	if !strings.Contains(raw, "aGVsbG8=") { // base64("hello")
		t.Fatal("attachment body was not base64 encoded")
	}
}

func TestBuildWithoutAttachmentsKeepsShape(t *testing.T) {
	msg, err := Build(Message{From: "a@b.c", To: "d@e.f", Subject: "s", HTML: "<p>x</p>"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if strings.Contains(string(msg), "multipart/mixed") {
		t.Fatal("plain message should not use multipart/mixed")
	}
}

func TestToBase64WrapsLines(t *testing.T) {
	out := toBase64(strings.Repeat("a", 300))
	for _, line := range strings.Split(out, "\r\n") {
		if len(line) > 76 {
			t.Fatalf("base64 line too long: %d", len(line))
		}
	}
}
