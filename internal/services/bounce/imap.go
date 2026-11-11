package bounce

// Minimal IMAP client, just enough to read delivery status notifications from
// a bounce mailbox. It speaks LOGIN / SELECT / UID SEARCH UNSEEN / UID FETCH /
// UID STORE and nothing else: no MIME indexing, no mailboxes management. The
// project builds offline, so this avoids pulling a full IMAP library.

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Config is one bounce mailbox connection.
type Config struct {
	Host       string
	Port       int
	User       string
	Pass       string
	TLSMode    string // starttls (default) | ssl | none
	Folder     string // default INBOX
	IgnoreCert bool
	Timeout    time.Duration
}

// Message is one fetched mailbox message.
type Message struct {
	UID int
	Raw []byte
}

// Client is an authenticated IMAP connection.
type Client struct {
	conn net.Conn
	r    *bufio.Reader
	cfg  Config
	tag  int
}

const defaultIMAPTimeout = 20 * time.Second

// Dial connects, negotiates TLS, logs in and selects the mailbox.
func Dial(cfg Config) (*Client, error) {
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		return nil, errors.New("IMAP host required")
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.TLSMode))
	port := cfg.Port
	if port <= 0 {
		if mode == "ssl" {
			port = 993
		} else {
			port = 143
		}
	}
	if mode == "" {
		if port == 993 {
			mode = "ssl"
		} else {
			mode = "starttls"
		}
	}
	if mode != "starttls" && mode != "ssl" && mode != "none" {
		return nil, errors.New("IMAP tls mode must be starttls, ssl or none")
	}
	if strings.TrimSpace(cfg.User) != "" && mode == "none" && !IsLoopbackHost(host) {
		return nil, errors.New("refusing to send IMAP credentials over plaintext to a remote host")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultIMAPTimeout
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.IgnoreCert {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
	} else {
		tlsCfg.ServerName = host
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if mode == "ssl" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	// Bound the whole conversation so a stuck server cannot pin the poller.
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	c := &Client{conn: conn, r: bufio.NewReader(conn), cfg: cfg}
	greeting, err := c.readLine()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !strings.HasPrefix(strings.ToUpper(greeting), "* OK") &&
		!strings.HasPrefix(strings.ToUpper(greeting), "* PREAUTH") {
		conn.Close()
		return nil, fmt.Errorf("IMAP greeting: %s", greeting)
	}
	if mode == "starttls" {
		if _, err := c.command("STARTTLS"); err != nil {
			conn.Close()
			return nil, err
		}
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("IMAP STARTTLS: %w", err)
		}
		c.conn = tlsConn
		c.r = bufio.NewReader(tlsConn)
	}
	if strings.TrimSpace(cfg.User) != "" {
		if _, err := c.command("LOGIN " + quote(cfg.User) + " " + quote(cfg.Pass)); err != nil {
			conn.Close()
			return nil, err
		}
	}
	folder := strings.TrimSpace(cfg.Folder)
	if folder == "" {
		folder = "INBOX"
	}
	if _, err := c.command("SELECT " + quote(folder)); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// Close logs out and drops the connection.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	_, _ = c.command("LOGOUT")
	return c.conn.Close()
}

// ListUnseen returns the newest unseen messages, up to limit.
func (c *Client) ListUnseen(limit int) ([]Message, error) {
	lines, err := c.command("UID SEARCH UNSEEN")
	if err != nil {
		return nil, err
	}
	var uids []int
	for _, l := range lines {
		if !strings.HasPrefix(strings.ToUpper(l), "* SEARCH") {
			continue
		}
		for _, f := range strings.Fields(l)[2:] {
			if n, err := strconv.Atoi(f); err == nil && n > 0 {
				uids = append(uids, n)
			}
		}
	}
	if len(uids) == 0 {
		return nil, nil
	}
	if limit > 0 && len(uids) > limit {
		uids = uids[len(uids)-limit:]
	}
	return c.fetch(uids)
}

// MarkSeen flags messages so the next poll does not read them again.
func (c *Client) MarkSeen(uids []int) error {
	if len(uids) == 0 {
		return nil
	}
	_, err := c.command("UID STORE " + uidSet(uids) + " +FLAGS.SILENT (\\Seen)")
	return err
}

// fetch reads UID + full body for each message. Bodies are requested with
// BODY.PEEK[] so fetching alone does not mark them seen.
func (c *Client) fetch(uids []int) ([]Message, error) {
	c.tag++
	tag := fmt.Sprintf("A%03d", c.tag)
	if _, err := c.conn.Write([]byte(tag + " UID FETCH " + uidSet(uids) + " (UID BODY.PEEK[])\r\n")); err != nil {
		return nil, err
	}
	var out []Message
	for {
		line, err := c.readLine()
		if err != nil {
			return out, err
		}
		if strings.HasPrefix(line, tag+" ") {
			if isOK(line) {
				return out, nil
			}
			return out, fmt.Errorf("IMAP FETCH failed: %s", line)
		}
		if !strings.HasPrefix(line, "* ") || !strings.Contains(strings.ToUpper(line), "FETCH") {
			continue
		}
		msg := Message{UID: parseUID(line)}
		size, hasLiteral := literalSize(line)
		if hasLiteral {
			body := make([]byte, size)
			if _, err := io.ReadFull(c.r, body); err != nil {
				return out, err
			}
			msg.Raw = body
			// The rest of the response line follows the literal, usually ")".
			tail, err := c.readLine()
			if err != nil {
				return out, err
			}
			if msg.UID == 0 {
				msg.UID = parseUID(tail)
			}
		}
		if msg.UID > 0 {
			out = append(out, msg)
		}
	}
}

func (c *Client) readLine() (string, error) {
	line, err := c.r.ReadString('\n')
	if err != nil {
		return strings.TrimRight(line, "\r\n"), err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// command sends one tagged command and drains its response until the tagged
// completion line arrives.
func (c *Client) command(line string) ([]string, error) {
	c.tag++
	tag := fmt.Sprintf("A%03d", c.tag)
	if _, err := c.conn.Write([]byte(tag + " " + line + "\r\n")); err != nil {
		return nil, err
	}
	var lines []string
	for {
		l, err := c.readLine()
		if err != nil {
			return lines, err
		}
		switch {
		case strings.HasPrefix(l, tag+" "):
			if isOK(l) {
				return lines, nil
			}
			return lines, fmt.Errorf("IMAP %s failed: %s", firstWord(line), l)
		case strings.HasPrefix(l, "* "):
			lines = append(lines, l)
		}
	}
}

func isOK(line string) bool {
	fields := strings.Fields(line)
	return len(fields) >= 2 && strings.EqualFold(fields[1], "OK")
}

func firstWord(s string) string {
	if i := strings.IndexByte(s, ' '); i > 0 {
		return s[:i]
	}
	return s
}

// parseUID extracts the UID value from a FETCH response line.
func parseUID(line string) int {
	up := strings.ToUpper(line)
	idx := strings.Index(up, "UID ")
	if idx < 0 {
		return 0
	}
	rest := strings.Fields(line[idx+4:])
	if len(rest) == 0 {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimRight(rest[0], ")"))
	if err != nil {
		return 0
	}
	return n
}

// literalSize returns the {N} literal length at the end of a response line.
func literalSize(line string) (int, bool) {
	open := strings.LastIndexByte(line, '{')
	closeIdx := strings.LastIndexByte(line, '}')
	if open < 0 || closeIdx < open {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(line[open+1 : closeIdx]))
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func uidSet(uids []int) string {
	parts := make([]string, 0, len(uids))
	for _, uid := range uids {
		parts = append(parts, strconv.Itoa(uid))
	}
	return strings.Join(parts, ",")
}

// quote escapes an IMAP string argument. CR/LF are folded to spaces so a
// username, password or mailbox name can never inject a second command.
func quote(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return ' '
		}
		return r
	}, s)
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// IsLoopbackHost reports whether host is the local machine, where plaintext
// IMAP is acceptable.
func IsLoopbackHost(host string) bool {
	h := strings.Trim(strings.ToLower(host), "[]")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
