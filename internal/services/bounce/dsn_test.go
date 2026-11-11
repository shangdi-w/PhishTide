package bounce

import (
	"strings"
	"testing"
)

const hardBounce = `From: Mail Delivery System <MAILER-DAEMON@mx.example.com>
To: ops@example.com
Subject: Undelivered Mail Returned to Sender
Content-Type: multipart/report; report-type=delivery-status;
	boundary="XYZ123"

--XYZ123
Content-Type: text/plain; charset=utf-8

Your message could not be delivered.
--XYZ123
Content-Type: message/delivery-status

Reporting-MTA: dns; mx.example.com
Arrival-Date: Thu, 6 Nov 2026 10:00:00 +0000

Final-Recipient: rfc822; Victim@Example.com
Original-Recipient: rfc822;victim@example.com
Action: failed
Status: 5.1.1
Remote-MTA: dns; mx.target.example
Diagnostic-Code: smtp; 550 5.1.1 <victim@example.com>: Recipient address rejected: User unknown

--XYZ123--
`

const softBounce = `From: Mail Delivery System <MAILER-DAEMON@mx.example.com>
To: ops@example.com
Subject: Delivery Status Notification (Delay)
Content-Type: multipart/report; report-type=delivery-status; boundary="abc"

--abc
Content-Type: message/delivery-status

Reporting-MTA: dns; mx.example.com

Final-Recipient: rfc822; slow@example.com
Action: delayed
Status: 4.4.1
Diagnostic-Code: smtp; 421 4.4.1 Connection timed out

--abc
Content-Type: message/delivery-status

Final-Recipient: rfc822; gone@example.com
Action: failed
Status: 5.2.2
Diagnostic-Code: smtp; 552 5.2.2 Mailbox full

--abc--
`

func TestParseDSNHardBounce(t *testing.T) {
	notices, ok := ParseDSN([]byte(hardBounce))
	if !ok || len(notices) != 1 {
		t.Fatalf("ok=%v notices=%+v", ok, notices)
	}
	n := notices[0]
	if n.Email != "victim@example.com" || n.Status != "5.1.1" || n.Action != "failed" {
		t.Fatalf("notice = %+v", n)
	}
	if !strings.Contains(n.Diagnostic, "User unknown") {
		t.Fatalf("diagnostic = %q", n.Diagnostic)
	}
	if kind := KindOf(n); kind != "hard" {
		t.Fatalf("kind = %s", kind)
	}
}

func TestParseDSNMultipleRecipients(t *testing.T) {
	notices, ok := ParseDSN([]byte(softBounce))
	if !ok || len(notices) != 2 {
		t.Fatalf("ok=%v notices=%+v", ok, notices)
	}
	if notices[0].Email != "slow@example.com" || KindOf(notices[0]) != "soft" {
		t.Fatalf("first = %+v kind=%s", notices[0], KindOf(notices[0]))
	}
	// 552 is a 5.x.x status: permanently rejected even though the text says full.
	if notices[1].Email != "gone@example.com" || KindOf(notices[1]) != "hard" {
		t.Fatalf("second = %+v kind=%s", notices[1], KindOf(notices[1]))
	}
}

func TestParseDSNXFailedRecipients(t *testing.T) {
	raw := `From: postmaster@example.com
To: ops@example.com
Subject: failure notice
X-Failed-Recipients: Bad@Example.com, other@example.com
Content-Type: text/plain

Hi. This is the qmail-send program.
<bad@example.com>: 550 5.1.1 no such user
`
	notices, ok := ParseDSN([]byte(raw))
	if !ok || len(notices) != 2 {
		t.Fatalf("ok=%v notices=%+v", ok, notices)
	}
	if notices[0].Email != "bad@example.com" || KindOf(notices[0]) != "hard" {
		t.Fatalf("notice = %+v", notices[0])
	}
	if notices[1].Email != "other@example.com" {
		t.Fatalf("second = %+v", notices[1])
	}
}

func TestParseDSNRejectsNormalMail(t *testing.T) {
	raw := `From: alice@example.com
To: ops@example.com
Subject: lunch?
Content-Type: text/plain

See you at noon.
`
	if notices, ok := ParseDSN([]byte(raw)); ok || len(notices) != 0 {
		t.Fatalf("ok=%v notices=%+v", ok, notices)
	}
}

func TestKindOfDelivered(t *testing.T) {
	if got := KindOf(Notice{Action: "delivered", Status: "2.0.0"}); got != "delivered" {
		t.Fatalf("kind = %s", got)
	}
}
