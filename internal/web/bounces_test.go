package web

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"phishsim/internal/core/store"
	"phishsim/internal/services/geoip"
)

const testHardBounce = `From: Mail Delivery System <MAILER-DAEMON@mx.example.com>
To: ops@example.com
Subject: Undelivered Mail Returned to Sender
Content-Type: multipart/report; report-type=delivery-status; boundary="B1"

--B1
Content-Type: message/delivery-status

Reporting-MTA: dns; mx.example.com

Final-Recipient: rfc822; victim@example.com
Action: failed
Status: 5.1.1
Diagnostic-Code: smtp; 550 5.1.1 <victim@example.com>: User unknown

--B1--
`

// startBounceIMAP serves one unseen DSN message and records STORE calls.
func startBounceIMAP(t *testing.T, body []byte) (int, *string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	marked := ""
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				fmt.Fprint(conn, "* OK ready\r\n")
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					f := strings.Fields(line)
					if len(f) < 2 {
						continue
					}
					tag, cmd := f[0], strings.ToUpper(f[1])
					switch {
					case cmd == "LOGIN":
						fmt.Fprintf(conn, "%s OK\r\n", tag)
					case cmd == "SELECT":
						fmt.Fprintf(conn, "* 1 EXISTS\r\n%s OK [READ-WRITE]\r\n", tag)
					case cmd == "UID" && len(f) > 2 && strings.EqualFold(f[2], "SEARCH"):
						fmt.Fprintf(conn, "* SEARCH 1\r\n%s OK\r\n", tag)
					case cmd == "UID" && len(f) > 2 && strings.EqualFold(f[2], "FETCH"):
						fmt.Fprintf(conn, "* 1 FETCH (UID 1 BODY[] {%d}\r\n", len(body))
						conn.Write(body)
						fmt.Fprint(conn, ")\r\n")
						fmt.Fprintf(conn, "%s OK\r\n", tag)
					case cmd == "UID" && len(f) > 2 && strings.EqualFold(f[2], "STORE"):
						mu.Lock()
						marked = line
						mu.Unlock()
						fmt.Fprintf(conn, "%s OK\r\n", tag)
					case cmd == "LOGOUT":
						fmt.Fprintf(conn, "* BYE\r\n%s OK\r\n", tag)
						return
					default:
						fmt.Fprintf(conn, "%s BAD\r\n", tag)
					}
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port, &marked
}

func TestPollBouncesRecordsHardBounce(t *testing.T) {
	s := newAgentServer(t)
	tpl, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	page, _ := s.Store.UpsertPage(store.LandingPage{Name: "p", Kind: "template", Body: "<p>x</p>"}, nil)
	gid, _ := s.Store.CreateGroup("g")
	if _, err := s.Store.AddTargetsToGroup(gid, []store.Target{{Email: "victim@example.com"}}); err != nil {
		t.Fatal(err)
	}
	cid, err := s.Store.CreateCampaign(store.Campaign{Name: "c", EmailTemplateID: tpl, LandingPageID: page}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	results, _ := s.Store.ListResults(cid)
	if len(results) != 1 {
		t.Fatalf("results = %d", len(results))
	}
	s.Store.MarkSent(results[0].ID)

	port, marked := startBounceIMAP(t, []byte(testHardBounce))
	for k, v := range map[string]string{
		settingBounceHost:   "127.0.0.1",
		settingBouncePort:   strconv.Itoa(port),
		settingBounceUser:   "ops@example.com",
		settingBouncePass:   s.Store.EncryptSetting("secret"),
		settingBounceTLS:    "none",
		settingBounceFolder: "INBOX",
	} {
		if err := s.putSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	cfg, ok := s.bounceConfig()
	if !ok {
		t.Fatal("bounce config not detected")
	}
	res, err := s.pollBounces(cfg, 10)
	if err != nil {
		t.Fatal(err)
	}
	if res.Messages != 1 || res.Notices != 1 || res.Hard != 1 || res.Stored != 1 {
		t.Fatalf("result = %+v", res)
	}

	list, err := s.Store.ListBounces(cid, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("bounces = %+v err=%v", list, err)
	}
	if list[0].Email != "victim@example.com" || list[0].Kind != "hard" || list[0].Status != "5.1.1" {
		t.Fatalf("bounce = %+v", list[0])
	}
	results, _ = s.Store.ListResults(cid)
	if results[0].Status != "bounced" {
		t.Fatalf("result status = %q", results[0].Status)
	}
	if !strings.Contains(*marked, "\\Seen") {
		t.Fatalf("message not marked seen: %q", *marked)
	}

	// The mailbox status endpoint renders the saved config without the password.
	st := s.bounceStatus()
	if st["configured"] != true || st["pass_set"] != true {
		t.Fatalf("status = %+v", st)
	}
}

func TestPollBouncesUnmatchedSender(t *testing.T) {
	s := newAgentServer(t)
	port, _ := startBounceIMAP(t, []byte(testHardBounce))
	for k, v := range map[string]string{
		settingBounceHost: "127.0.0.1",
		settingBouncePort: strconv.Itoa(port),
		settingBounceTLS:  "none",
	} {
		if err := s.putSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	cfg, _ := s.bounceConfig()
	res, err := s.pollBounces(cfg, 10)
	if err != nil {
		t.Fatal(err)
	}
	if res.Hard != 1 || res.Unmatched != 1 {
		t.Fatalf("result = %+v", res)
	}
	all, _ := s.Store.ListAllBounces(10)
	if len(all) != 1 || all[0].CampaignID != 0 {
		t.Fatalf("all = %+v", all)
	}
}

func TestSaveBounceConfigDefaults(t *testing.T) {
	s := newAgentServer(t)
	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/__admin/api/bounces/config", strings.NewReader(body))
		s.adminSaveBounceConfig(rr, req)
		return rr
	}
	// Plaintext IMAP to a remote host would expose the mailbox password.
	if rr := post(`{"host":"imap.example.com","port":143,"user":"u","password":"p","tls_mode":"none"}`); rr.Code != 400 {
		t.Fatalf("remote plaintext = %d %s", rr.Code, rr.Body.String())
	}
	if rr := post(`{"host":"127.0.0.1","port":143,"user":"u","password":"p","tls_mode":"none"}`); rr.Code != 200 {
		t.Fatalf("loopback plaintext = %d %s", rr.Code, rr.Body.String())
	}
	if st := s.bounceStatus(); st["ignore_cert"] != false || st["pass_set"] != true {
		t.Fatalf("defaults = %+v", st)
	}
	// Leaving the password empty keeps the stored one.
	if rr := post(`{"host":"127.0.0.1","port":143,"user":"u","tls_mode":"none"}`); rr.Code != 200 {
		t.Fatalf("reuse password = %d %s", rr.Code, rr.Body.String())
	}
	if st := s.bounceStatus(); st["pass_set"] != true {
		t.Fatalf("password lost on resave: %+v", st)
	}
	if rr := post(`{"host":"127.0.0.1","tls_mode":"plain"}`); rr.Code != 400 {
		t.Fatalf("bad tls mode = %d %s", rr.Code, rr.Body.String())
	}
}

func TestGeoLookupTool(t *testing.T) {
	s := newAgentServer(t)
	if _, ok, note := execTool(t, s, 0, "geo_lookup", map[string]any{"ip": "8.8.8.8"}); ok {
		t.Fatalf("lookup without a database should fail: %s", note)
	}

	path := filepath.Join(t.TempDir(), "ip2asn.tsv")
	body := "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.\n" +
		"114.114.0.0\t114.114.255.255\t4134\tCN\tCHINANET-BACKBONE\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := geoip.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Geo = db

	out, ok, note := execTool(t, s, 0, "geo_lookup", map[string]any{"ip": "114.114.114.114, 192.168.1.5"})
	if !ok {
		t.Fatalf("geo_lookup failed: %s", note)
	}
	if int(out["count"].(float64)) != 2 || int(out["found"].(float64)) != 1 {
		t.Fatalf("out = %+v", out)
	}
	rows := out["results"].([]any)
	first := rows[0].(map[string]any)
	if first["found"] != true || first["country"] != "中国" || first["org"] != "CHINANET-BACKBONE" || first["asn"] != "4134" {
		t.Fatalf("first row = %+v", first)
	}
	second := rows[1].(map[string]any)
	if second["found"] != false || second["class"] != "内网" {
		t.Fatalf("second row = %+v", second)
	}
}

func TestListBouncesTool(t *testing.T) {
	s := newAgentServer(t)
	if err := s.Store.RecordBounce(store.Bounce{CampaignID: 5, ResultID: 9, Email: "a@example.com", Kind: "hard", Status: "5.1.1"}); err != nil {
		t.Fatal(err)
	}
	out, ok, note := execTool(t, s, 0, "list_bounces", map[string]any{"campaign_id": 5})
	if !ok {
		t.Fatalf("tool failed: %s", note)
	}
	if int(out["count"].(float64)) != 1 {
		t.Fatalf("out = %+v", out)
	}
	counts := out["counts"].(map[string]any)
	if int(counts["hard"].(float64)) != 1 {
		t.Fatalf("counts = %+v", counts)
	}
	// Sorted output is easiest to assert for the all-campaigns mode.
	all, ok, _ := execTool(t, s, 0, "list_bounces", map[string]any{})
	if !ok || int(all["count"].(float64)) != 1 {
		t.Fatalf("all = %+v", all)
	}
}
