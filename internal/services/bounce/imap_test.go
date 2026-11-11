package bounce

import (
	"bufio"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIMAP is a tiny IMAP server that serves a fixed set of unseen messages.
type fakeIMAP struct {
	ln       net.Listener
	mu       sync.Mutex
	commands []string
	marked   string
}

func startFakeIMAP(t *testing.T, messages map[int][]byte) *fakeIMAP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIMAP{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn, messages)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeIMAP) serve(conn net.Conn, messages map[int][]byte) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	fmt.Fprint(conn, "* OK fake imap ready\r\n")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		tag, cmd := fields[0], strings.ToUpper(fields[1])
		f.mu.Lock()
		f.commands = append(f.commands, line)
		f.mu.Unlock()
		switch {
		case cmd == "LOGIN":
			fmt.Fprintf(conn, "%s OK logged in\r\n", tag)
		case cmd == "SELECT":
			fmt.Fprintf(conn, "* %d EXISTS\r\n%s OK [READ-WRITE] selected\r\n", len(messages), tag)
		case cmd == "UID" && len(fields) >= 3 && strings.EqualFold(fields[2], "SEARCH"):
			uids := make([]int, 0, len(messages))
			for uid := range messages {
				uids = append(uids, uid)
			}
			sort.Ints(uids)
			parts := make([]string, 0, len(uids))
			for _, uid := range uids {
				parts = append(parts, strconv.Itoa(uid))
			}
			fmt.Fprintf(conn, "* SEARCH %s\r\n%s OK\r\n", strings.Join(parts, " "), tag)
		case cmd == "UID" && len(fields) >= 3 && strings.EqualFold(fields[2], "FETCH"):
			want := map[int]bool{}
			if len(fields) >= 4 {
				for _, s := range strings.Split(fields[3], ",") {
					if n, err := strconv.Atoi(s); err == nil {
						want[n] = true
					}
				}
			}
			uids := make([]int, 0, len(want))
			for uid := range want {
				if _, ok := messages[uid]; ok {
					uids = append(uids, uid)
				}
			}
			sort.Ints(uids)
			for seq, uid := range uids {
				body := messages[uid]
				fmt.Fprintf(conn, "* %d FETCH (UID %d BODY[] {%d}\r\n", seq+1, uid, len(body))
				conn.Write(body)
				fmt.Fprint(conn, ")\r\n")
			}
			fmt.Fprintf(conn, "%s OK\r\n", tag)
		case cmd == "UID" && len(fields) >= 3 && strings.EqualFold(fields[2], "STORE"):
			f.mu.Lock()
			f.marked = line
			f.mu.Unlock()
			fmt.Fprintf(conn, "%s OK\r\n", tag)
		case cmd == "LOGOUT":
			fmt.Fprintf(conn, "* BYE\r\n%s OK\r\n", tag)
			return
		default:
			fmt.Fprintf(conn, "%s BAD unknown\r\n", tag)
		}
	}
}

func TestIMAPListUnseenAndMarkSeen(t *testing.T) {
	msgs := map[int][]byte{
		10: []byte("Subject: bounce one\r\n\r\nbody"),
		11: []byte("Subject: bounce two\r\n\r\nbody2"),
	}
	f := startFakeIMAP(t, msgs)
	addr := f.ln.Addr().(*net.TCPAddr)

	c, err := Dial(Config{Host: "127.0.0.1", Port: addr.Port, User: "ops@example.com", Pass: "secret", TLSMode: "none"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.ListUnseen(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("messages = %d: %+v", len(got), got)
	}
	for _, m := range got {
		if string(m.Raw) != string(msgs[m.UID]) {
			t.Fatalf("uid %d body = %q", m.UID, m.Raw)
		}
	}
	uids := []int{got[0].UID, got[1].UID}
	if err := c.MarkSeen(uids); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.Contains(f.marked, "+FLAGS.SILENT (\\Seen)") {
		t.Fatalf("store command not seen: %q (commands=%v)", f.marked, f.commands)
	}
	if !strings.Contains(f.marked, strconv.Itoa(uids[0])) {
		t.Fatalf("store command missing uid: %q", f.marked)
	}
}

func TestIMAPLimitKeepsNewest(t *testing.T) {
	msgs := map[int][]byte{1: []byte("a"), 2: []byte("b"), 3: []byte("c")}
	f := startFakeIMAP(t, msgs)
	addr := f.ln.Addr().(*net.TCPAddr)
	c, err := Dial(Config{Host: "127.0.0.1", Port: addr.Port, TLSMode: "none", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got, err := c.ListUnseen(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].UID != 3 {
		t.Fatalf("got %+v", got)
	}
}

func TestDialRejectsPlaintextRemoteCredentials(t *testing.T) {
	_, err := Dial(Config{Host: "smtp.example.com", Port: 143, User: "u", Pass: "p", TLSMode: "none"})
	if err == nil || !strings.Contains(err.Error(), "plaintext") {
		t.Fatalf("err = %v", err)
	}
}
