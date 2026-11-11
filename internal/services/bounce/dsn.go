package bounce

// Delivery status notification parsing (RFC 3464). A bounce message is usually
// multipart/report with a message/delivery-status part: the first header block
// describes the report, every later block describes one failed recipient with
// Final-Recipient / Action / Status / Diagnostic-Code. Some MTAs instead put
// the failed addresses in X-Failed-Recipients; that form is accepted too.

import (
	"bufio"
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
)

// Notice is one recipient verdict inside a bounce.
type Notice struct {
	Email      string
	Action     string // failed | delayed | delivered
	Status     string // enhanced status code, e.g. 5.1.1
	Diagnostic string
}

const maxDSNBody = 5 << 20

var enhancedStatusRe = regexp.MustCompile(`\b([45]\.\d{1,3}\.\d{1,3})\b`)

// ParseDSN extracts per-recipient notices from a bounce message. ok is false
// when the message is not a bounce at all (a normal reply in the mailbox).
func ParseDSN(raw []byte) (notices []Notice, ok bool) {
	if len(raw) == 0 || len(raw) > maxDSNBody {
		return nil, false
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, false
	}
	ctype := msg.Header.Get("Content-Type")
	mediaType, params, _ := mime.ParseMediaType(ctype)

	switch {
	case strings.HasPrefix(mediaType, "multipart/"):
		notices = walkParts(msg.Body, params["boundary"], 0)
		if len(notices) > 0 {
			return notices, true
		}
	case mediaType == "message/delivery-status":
		notices = parseStatusBody(msg.Body)
		if len(notices) > 0 {
			return notices, true
		}
	}

	// Non-DSN fallback: X-Failed-Recipients lists the rejected addresses.
	if addrs := strings.TrimSpace(msg.Header.Get("X-Failed-Recipients")); addrs != "" {
		diag := scanDiagnostic(raw)
		status := ""
		if m := enhancedStatusRe.FindStringSubmatch(diag); m != nil {
			status = m[1]
		}
		for _, a := range strings.Split(addrs, ",") {
			a = normalizeAddress(a)
			if a == "" {
				continue
			}
			notices = append(notices, Notice{
				Email:      a,
				Action:     "failed",
				Status:     status,
				Diagnostic: diag,
			})
		}
		if len(notices) > 0 {
			return notices, true
		}
	}
	return nil, false
}

// walkParts recursively looks for message/delivery-status parts.
func walkParts(r io.Reader, boundary string, depth int) []Notice {
	if boundary == "" || depth > 4 {
		return nil
	}
	mr := multipart.NewReader(r, boundary)
	var out []Notice
	for {
		part, err := mr.NextPart()
		if err != nil {
			return out
		}
		mediaType, params, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		switch {
		case mediaType == "message/delivery-status" || mediaType == "message/global-delivery-status":
			out = append(out, parseStatusBody(part)...)
		case strings.HasPrefix(mediaType, "multipart/"):
			out = append(out, walkParts(part, params["boundary"], depth+1)...)
		}
		_ = part.Close()
	}
}

// parseStatusBody reads the per-recipient header blocks of a delivery-status
// body. Blocks without Final-Recipient/Original-Recipient are report headers
// and are skipped.
func parseStatusBody(r io.Reader) []Notice {
	tp := textproto.NewReader(bufio.NewReader(r))
	var out []Notice
	for {
		// ReadMIMEHeader returns io.EOF together with the last block when the
		// body does not end in a blank line, so process the header first.
		h, err := tp.ReadMIMEHeader()
		if len(h) == 0 {
			if err != nil {
				return out
			}
			continue
		}
		addr := recipientOf(h)
		if addr == "" {
			continue // per-message block
		}
		n := Notice{
			Email:      addr,
			Action:     strings.ToLower(strings.TrimSpace(h.Get("Action"))),
			Status:     strings.TrimSpace(h.Get("Status")),
			Diagnostic: strings.TrimSpace(h.Get("Diagnostic-Code")),
		}
		if n.Status == "" {
			if m := enhancedStatusRe.FindStringSubmatch(n.Diagnostic); m != nil {
				n.Status = m[1]
			}
		}
		out = append(out, n)
	}
}

func recipientOf(h textproto.MIMEHeader) string {
	for _, key := range []string{"Final-Recipient", "Original-Recipient"} {
		v := h.Get(key)
		if v == "" {
			continue
		}
		if i := strings.IndexByte(v, ';'); i >= 0 {
			v = v[i+1:]
		}
		if addr := normalizeAddress(v); addr != "" {
			return addr
		}
	}
	return ""
}

func normalizeAddress(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "<>")
	v = strings.TrimSpace(v)
	if !strings.Contains(v, "@") || strings.ContainsAny(v, " \t") {
		return ""
	}
	return strings.ToLower(v)
}

// scanDiagnostic finds an SMTP diagnostic code in a plain-text bounce.
func scanDiagnostic(raw []byte) string {
	text := string(raw)
	if m := regexp.MustCompile(`(?i)(?:^|\n)((?:smtp;)?\s*[45]\d\d[ -].{0,200})`).FindStringSubmatch(text); m != nil {
		return strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(m[1]), "\r", " "))
	}
	if m := enhancedStatusRe.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

// KindOf maps a notice to hard/soft/delivered.
func KindOf(n Notice) string {
	status := strings.TrimSpace(n.Status)
	if status == "" {
		if m := enhancedStatusRe.FindStringSubmatch(n.Diagnostic); m != nil {
			status = m[1]
		}
	}
	switch {
	case strings.HasPrefix(status, "5"):
		return "hard"
	case strings.HasPrefix(status, "4"):
		return "soft"
	case strings.EqualFold(n.Action, "delivered"), strings.EqualFold(n.Action, "relayed"):
		return "delivered"
	case strings.EqualFold(n.Action, "delayed"):
		return "soft"
	}
	// "failed" without a status is a permanent rejection.
	if strings.EqualFold(n.Action, "failed") {
		return "hard"
	}
	return "soft"
}
