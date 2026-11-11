// Package email renders phishing email templates per target and (optionally)
// sends them over SMTP. Generation works without any SMTP configuration; the
// platform is useful for content generation and manual send alone.
package email

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Context carries the per-target variables available to every template.
type Context struct {
	FirstName      string
	LastName       string
	Email          string
	Position       string
	TrackingURL    string
	TrackingPixel  string
	ReportURL      string
	UnsubscribeURL string
	FromName       string
	FromEmail      string
	Subject        string
}

// Rendered is one fully-expanded email.
type Rendered struct {
	Subject string
	HTML    string
	Text    string
}

// Render expands a subject, html, and text template against ctx. Template
// syntax errors are returned so a bad template is caught at generation time,
// not at send time.
func Render(subjectTmpl, htmlTmpl, textTmpl string, ctx Context) (Rendered, error) {
	funcs := template.FuncMap{}
	subject, err := renderOne("subject", subjectTmpl, ctx, funcs)
	if err != nil {
		return Rendered{}, err
	}
	html, err := renderOne("html", htmlTmpl, ctx, funcs)
	if err != nil {
		return Rendered{}, err
	}
	text, err := renderOne("text", textTmpl, ctx, funcs)
	if err != nil {
		return Rendered{}, err
	}
	return Rendered{Subject: subject, HTML: html, Text: text}, nil
}

func renderOne(name, tmpl string, ctx Context, funcs template.FuncMap) (string, error) {
	if strings.TrimSpace(tmpl) == "" {
		return "", nil
	}
	t, err := template.New(name).Funcs(funcs).Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("parse %s template: %w", name, err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, ctx); err != nil {
		return "", fmt.Errorf("render %s template: %w", name, err)
	}
	return buf.String(), nil
}

// SMTPConfig holds the optional outbound mail settings.
type SMTPConfig struct {
	Host       string
	Port       int
	User       string
	Pass       string
	TLSMode    string // "none" | "starttls" | "ssl"
	From       string
	IgnoreCert bool
}

// FromDisplay renders a "Name <email>" From header value.
func FromDisplay(name, addr string) string {
	name = sanitizeHeader(name)
	if name == "" {
		return sanitizeHeader(addr)
	}
	return fmt.Sprintf("%s <%s>", name, sanitizeHeader(addr))
}

// Attachment is one file delivered with the email.
type Attachment struct {
	Name        string
	ContentType string
	Body        []byte
}

// Message is one RFC822 message ready to send.
type Message struct {
	From        string
	To          string
	Subject     string
	HTML        string
	Text        string
	Attachments []Attachment
}

// Build assembles the MIME message from a rendered email. Without attachments
// it is a multipart/alternative (or a bare HTML part); with attachments the
// alternative entity is wrapped in multipart/mixed.
func Build(m Message) ([]byte, error) {
	// Header values can be influenced by per-target data (subject templates,
	// display names). A CR/LF would inject arbitrary headers or SMTP commands,
	// so reject it outright instead of silently stripping it.
	if strings.ContainsAny(m.To, "\r\n") || strings.ContainsAny(m.From, "\r\n") {
		return nil, errors.New("invalid address: header injection characters")
	}
	if strings.TrimSpace(m.To) == "" {
		return nil, errors.New("empty recipient")
	}
	var b bytes.Buffer
	from := sanitizeHeader(m.From)
	writeHeader := func(k, v string) {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteString("\r\n")
	}
	writeHeader("From", from)
	writeHeader("To", sanitizeHeader(m.To))
	writeHeader("Subject", mimeHeader(m.Subject))
	writeHeader("Date", time.Now().Format(time.RFC1123Z))
	writeHeader("Message-ID", newMessageID(from))
	writeHeader("MIME-Version", "1.0")

	if len(m.Attachments) == 0 {
		if m.Text == "" {
			writeHeader("Content-Type", `text/html; charset="utf-8"`)
			writeHeader("Content-Transfer-Encoding", "base64")
			b.WriteString("\r\n")
			b.WriteString(toBase64(m.HTML))
			return b.Bytes(), nil
		}
		boundary := newBoundary()
		writeHeader("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
		b.WriteString("\r\n")
		writeAlternative(&b, boundary, m)
		return b.Bytes(), nil
	}

	// Outer multipart/mixed: the body entity first, then each attachment.
	outer := newBoundary()
	writeHeader("Content-Type", `multipart/mixed; boundary="`+outer+`"`)
	b.WriteString("\r\n")

	b.WriteString("--" + outer + "\r\n")
	if m.Text == "" {
		b.WriteString(`Content-Type: text/html; charset="utf-8"` + "\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		b.WriteString(toBase64(m.HTML))
		b.WriteString("\r\n")
	} else {
		inner := newBoundary()
		b.WriteString(`Content-Type: multipart/alternative; boundary="` + inner + `"` + "\r\n\r\n")
		writeAlternative(&b, inner, m)
	}

	for _, a := range m.Attachments {
		if len(a.Body) == 0 {
			continue
		}
		ct := sanitizeHeader(strings.TrimSpace(a.ContentType))
		if ct == "" || !strings.Contains(ct, "/") {
			ct = "application/octet-stream"
		}
		b.WriteString("--" + outer + "\r\n")
		b.WriteString("Content-Type: " + ct + `; name="` + filenameHeader(a.Name) + `"` + "\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n")
		b.WriteString("Content-Disposition: attachment; " + dispositionFilename(a.Name) + "\r\n\r\n")
		b.WriteString(toBase64(string(a.Body)))
		b.WriteString("\r\n")
	}
	b.WriteString("--" + outer + "--\r\n")
	return b.Bytes(), nil
}

// writeAlternative writes the quoted-printable text part and the base64 HTML
// part of one multipart/alternative entity, including the closing boundary.
func writeAlternative(b *bytes.Buffer, boundary string, m Message) {
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString(`Content-Type: text/plain; charset="utf-8"` + "\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	b.WriteString(qpEncode(m.Text))
	b.WriteString("\r\n")

	b.WriteString("--" + boundary + "\r\n")
	b.WriteString(`Content-Type: text/html; charset="utf-8"` + "\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(toBase64(m.HTML))
	b.WriteString("\r\n")

	b.WriteString("--" + boundary + "--\r\n")
}

// newBoundary returns a boundary unlikely to occur inside the body.
func newBoundary() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "phishsim-boundary-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return "phishsim-" + hex.EncodeToString(buf)
}

// newMessageID builds a globally unique Message-ID using the sender domain so
// the platform can later reconcile sends with provider logs.
func newMessageID(from string) string {
	domain := "phishsim.local"
	if at := strings.LastIndexByte(from, '@'); at >= 0 {
		d := strings.Trim(strings.TrimSpace(from[at+1:]), ">")
		if d != "" {
			domain = d
		}
	}
	return "<" + newBoundary() + "@" + domain + ">"
}

var messageIDRe = regexp.MustCompile(`(?mi)^Message-ID:\s*(<[^>]+>)`)

// MessageID extracts the Message-ID header from a built message.
func MessageID(msg []byte) string {
	if m := messageIDRe.FindSubmatch(msg); m != nil {
		return string(m[1])
	}
	return ""
}

// filenameHeader renders a filename safe for a quoted Content-Type parameter.
func filenameHeader(name string) string {
	name = sanitizeFilename(name)
	if isASCII(name) {
		return name
	}
	return mime.QEncoding.Encode("utf-8", name)
}

// dispositionFilename builds the Content-Disposition filename parameters,
// adding the RFC 5987 filename* form when the name is not ASCII.
func dispositionFilename(name string) string {
	name = sanitizeFilename(name)
	if name == "" {
		name = "attachment"
	}
	if isASCII(name) {
		return `filename="` + name + `"`
	}
	return `filename="` + asciiFallback(name) + `"; filename*=UTF-8''` + rfc5987Escape(name)
}

// sanitizeFilename strips characters that would break MIME headers or paths.
func sanitizeFilename(name string) string {
	name = strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '"', '\\', '/', 0:
			return -1
		}
		return r
	}, name)
	return strings.TrimSpace(name)
}

// asciiFallback keeps the ASCII characters of a filename and replaces the rest.
func asciiFallback(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r < 0x80 && r > 0x20 {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" || out == "_" {
		return "attachment"
	}
	return out
}

// rfc5987Escape percent-encodes a UTF-8 string for the filename* parameter.
func rfc5987Escape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '!' || c == '#' || c == '$' || c == '&' || c == '+' || c == '-' ||
			c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

// Send delivers a message over SMTP. cfg.TLSMode selects the transport:
// "ssl" (implicit TLS, port 465), "starttls" (explicit, port 587, the
// default), or "none" (plaintext). Authentication is used when a username is
// configured.
func Send(cfg SMTPConfig, msg []byte, to string) error {
	if strings.ContainsAny(to, "\r\n") {
		return errors.New("invalid recipient: header injection characters")
	}
	if strings.TrimSpace(cfg.Host) == "" {
		return errors.New("SMTP host required")
	}
	port := cfg.Port
	if port <= 0 {
		port = 587
	}
	mode := cfg.TLSMode
	if mode == "" {
		mode = "starttls"
	}
	// Port 465 is smtps (implicit TLS); STARTTLS on it makes the server drop
	// the connection.
	if port == 465 {
		mode = "ssl"
	}
	// Plaintext SMTP sends the password in the clear. Only allow it against a
	// loopback relay; remote hosts must use STARTTLS or implicit TLS.
	if cfg.User != "" && mode == "none" && !isLoopbackHost(cfg.Host) {
		return errors.New("refusing to send SMTP credentials over plaintext to a remote host")
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(port))
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.IgnoreCert {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
	} else {
		tlsCfg.ServerName = cfg.Host
	}

	dialer := &net.Dialer{Timeout: 30 * time.Second}
	implicitTLS := mode == "ssl"
	var raw net.Conn
	var err error
	if implicitTLS {
		raw, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		raw, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	// Bound the whole SMTP conversation so a hung server cannot pin a sending
	// goroutine forever.
	_ = raw.SetDeadline(time.Now().Add(2 * time.Minute))

	conn, err := smtp.NewClient(raw, cfg.Host)
	if err != nil {
		_ = raw.Close()
		return err
	}
	if !implicitTLS && mode != "none" {
		if err := conn.StartTLS(tlsCfg); err != nil {
			_ = conn.Close()
			return err
		}
	}
	defer conn.Close()

	if cfg.User != "" {
		if err := conn.Auth(smtp.PlainAuth("", cfg.User, cfg.Pass, cfg.Host)); err != nil {
			return err
		}
	}
	from := cfg.From
	if from == "" {
		from = cfg.User
	}
	if err := conn.Mail(from); err != nil {
		return err
	}
	if err := conn.Rcpt(to); err != nil {
		return err
	}
	w, err := conn.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return conn.Quit()
}

// isLoopbackHost reports whether host is localhost or a loopback IP.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// mimeHeader encodes a header value for non-ASCII subjects.
func mimeHeader(s string) string {
	s = sanitizeHeader(s)
	if isASCII(s) {
		return s
	}
	return "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?="
}

// sanitizeHeader neutralises characters that can terminate a header line by
// folding them to spaces (rejecting outright would drop otherwise valid mail
// for a single odd display name).
func sanitizeHeader(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return ' '
		}
		return r
	}, s)
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}

func qpEncode(s string) string {
	var b bytes.Buffer
	w := quotedprintable.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.String()
}

// toBase64 encodes a body part and wraps it at the RFC 2045 line limit.
func toBase64(s string) string {
	enc := base64.StdEncoding.EncodeToString([]byte(s))
	var b strings.Builder
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteString("\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc)
	return b.String()
}
