package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAddTargetsToGroupRejectsMalformedEmails(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "targets.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	gid, err := s.CreateGroup("validation")
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.AddTargetsToGroup(gid, []Target{
		{Email: "ok@example.com"},
		{Email: "victim@example.com\r\nBcc: evil@example.com"},
		{Email: "no-at-sign"},
		{Email: "  spaced@example.com  "},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("added %d targets, want 2", n)
	}
	got, err := s.ListGroupTargets(gid)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Email != "ok@example.com" || got[1].Email != "spaced@example.com" {
		t.Fatalf("unexpected targets: %+v", got)
	}
}

func TestPurgeOlderThanKeepsRecentRows(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "purge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	old := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339Nano)
	fresh := time.Now().UTC().Format(time.RFC3339Nano)
	for _, ts := range []string{old, fresh} {
		if _, err := s.db.Exec(`INSERT INTO submissions(campaign_id, result_id, ts, ip, user_agent, referer, username, password, fields)
			VALUES (?, ?, ?, '', '', '', '', '', '{}')`, 1, 1, ts); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`INSERT INTO events(campaign_id, target_id, kind, ip, user_agent, referer, detail, ts)
			VALUES (?, ?, 'opened', '', '', '', '', ?)`, 1, 1, ts); err != nil {
			t.Fatal(err)
		}
	}
	subs, events, err := s.PurgeOlderThan(time.Now().Add(-24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if subs != 1 || events != 1 {
		t.Fatalf("purged submissions=%d events=%d, want 1/1", subs, events)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM submissions`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("recent submission lost: n=%d err=%v", n, err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("recent event lost: n=%d err=%v", n, err)
	}
}

func TestCapturedFieldsAreEncryptedAtRest(t *testing.T) {
	s := &Store{secretKey: make([]byte, 32)}
	enc := s.encryptSecret(`{"username":"alice"}`)
	if !strings.HasPrefix(enc, "enc:v1:") {
		t.Fatalf("fields were not encrypted: %q", enc)
	}
	if got := s.decryptSecret(enc); got != `{"username":"alice"}` {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
	// Legacy plaintext rows must still be readable.
	if got := s.decryptSecret(`{"username":"legacy"}`); got != `{"username":"legacy"}` {
		t.Fatalf("legacy plaintext broken: %q", got)
	}
}

func TestDeleteTargetRefusesUsedTarget(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "deltarget.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	gid, err := s.CreateGroup("g")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddTargetsToGroup(gid, []Target{{Email: "a@example.com"}, {Email: "b@example.com"}}); err != nil {
		t.Fatal(err)
	}
	targets, err := s.ListGroupTargets(gid)
	if err != nil || len(targets) != 2 {
		t.Fatalf("targets: %v %d", err, len(targets))
	}
	// Unused target can be removed.
	if err := s.DeleteTarget(gid, targets[0].ID); err != nil {
		t.Fatalf("delete unused target: %v", err)
	}
	// Put the remaining target into a campaign; it must no longer be removable.
	tid, err := s.UpsertTemplate(EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	if err != nil {
		t.Fatal(err)
	}
	pid, err := s.UpsertPage(LandingPage{Name: "p", Kind: "template", Body: "<p>x</p>", CaptureCredentials: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateCampaign(Campaign{Name: "c", EmailTemplateID: tid, LandingPageID: pid}, []int64{gid}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteTarget(gid, targets[1].ID); err == nil {
		t.Fatal("target used by a campaign was deleted")
	}
}

func TestTemplateDefaultLandingPage(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "tplpage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tid, err := s.UpsertTemplate(EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	if err != nil {
		t.Fatal(err)
	}
	pid, err := s.UpsertPage(LandingPage{Name: "p", Kind: "template", Body: "<p>x</p>", CaptureCredentials: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetTemplateDefaultPage(tid, pid); err != nil {
		t.Fatal(err)
	}
	if got := s.TemplateDefaultPage(tid); got != pid {
		t.Fatalf("default page = %d, want %d", got, pid)
	}
	list, err := s.ListTemplates()
	if err != nil || len(list) == 0 || list[0].DefaultLandingPageID != pid {
		t.Fatalf("ListTemplates default page: %+v err=%v", list, err)
	}
	if err := s.SetTemplateDefaultPage(tid, 0); err != nil {
		t.Fatal(err)
	}
	if got := s.TemplateDefaultPage(tid); got != 0 {
		t.Fatalf("default page not cleared: %d", got)
	}
}

func TestDeleteCampaignResult(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "delresult.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tid, _ := s.UpsertTemplate(EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	pid, _ := s.UpsertPage(LandingPage{Name: "p", Kind: "template", Body: "<p>x</p>", CaptureCredentials: true}, nil)
	gid, _ := s.CreateGroup("g")
	if _, err := s.AddTargetsToGroup(gid, []Target{{Email: "a@example.com"}, {Email: "b@example.com"}}); err != nil {
		t.Fatal(err)
	}
	cid, err := s.CreateCampaign(Campaign{Name: "c", EmailTemplateID: tid, LandingPageID: pid}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	results, err := s.ListResults(cid)
	if err != nil || len(results) != 2 {
		t.Fatalf("results: %v %d", err, len(results))
	}
	if err := s.DeleteCampaignResult(cid, results[0].ID); err != nil {
		t.Fatalf("delete unsent result: %v", err)
	}
	results, _ = s.ListResults(cid)
	if len(results) != 1 {
		t.Fatalf("result not removed, left %d", len(results))
	}
	// A sent result must be refused.
	s.MarkSent(results[0].ID)
	if err := s.DeleteCampaignResult(cid, results[0].ID); err == nil {
		t.Fatal("sent result was removed")
	}
}

func TestResetCampaignSent(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "resend.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tid, _ := s.UpsertTemplate(EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	pid, _ := s.UpsertPage(LandingPage{Name: "p", Kind: "template", Body: "<p>x</p>", CaptureCredentials: true}, nil)
	gid, _ := s.CreateGroup("g")
	if _, err := s.AddTargetsToGroup(gid, []Target{{Email: "a@example.com"}}); err != nil {
		t.Fatal(err)
	}
	cid, err := s.CreateCampaign(Campaign{Name: "c", EmailTemplateID: tid, LandingPageID: pid}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	results, _ := s.ListResults(cid)
	s.MarkSent(results[0].ID)
	results, _ = s.ListResults(cid)
	if !results[0].Sent {
		t.Fatal("MarkSent did not set sent")
	}
	if err := s.ResetCampaignSent(cid); err != nil {
		t.Fatal(err)
	}
	results, _ = s.ListResults(cid)
	if results[0].Sent {
		t.Fatal("ResetCampaignSent did not clear sent")
	}
}

func uniq(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// exercise runs a full flow against an opened store and asserts the core
// invariants hold regardless of dialect.
func exercise(t *testing.T, s *Store) {
	t.Helper()
	tid, err := s.UpsertTemplate(EmailTemplate{
		Name: uniq("tpl"), Subject: "测试主题", HTML: "<p>hi {{.Email}}</p>", Text: "hi {{.Email}}",
	})
	if err != nil {
		t.Fatalf("upsert template: %v", err)
	}
	pageID, err := s.UpsertPage(LandingPage{
		Name: uniq("page"), Kind: "template",
		Body:               "<form action=__SUBMIT_URL__><input name=username><input name=password></form>",
		ContentType:        "text/html; charset=utf-8",
		CaptureCredentials: true,
		CapturePasswords:   true,
	}, nil)
	if err != nil {
		t.Fatalf("upsert page: %v", err)
	}

	gid, err := s.CreateGroup(uniq("grp"))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, err := s.AddTargetsToGroup(gid, []Target{
		{Email: uniq("a") + "@company.com", FirstName: "三", LastName: "张"},
		{Email: uniq("b") + "@company.com", FirstName: "四", LastName: "李"},
	}); err != nil {
		t.Fatalf("add targets: %v", err)
	}

	cid, err := s.CreateCampaign(Campaign{
		Name:            uniq("camp"),
		EmailTemplateID: tid,
		LandingPageID:   pageID,
	}, []int64{gid})
	if err != nil {
		t.Fatalf("create campaign: %v", err)
	}

	results, err := s.ListResults(cid)
	if err != nil || len(results) != 2 {
		t.Fatalf("list results: n=%d err=%v", len(results), err)
	}
	if results[0].Rid == "" {
		t.Fatal("result has empty rid")
	}

	// Submission round-trip.
	r := results[0]
	if err := s.RecordSubmission(r, "1.2.3.4", "ua", "https://ref", "alice", "s3cret", map[string][]string{"otp": {"123"}}); err != nil {
		t.Fatalf("record submission: %v", err)
	}
	subs, err := s.ListSubmissions(cid)
	if err != nil || len(subs) != 1 || subs[0].Username != "alice" || subs[0].Password != "s3cret" {
		t.Fatalf("submissions: n=%d err=%v", len(subs), err)
	}

	// Sending profile encryption round-trip.
	pid, err := s.UpsertSendingProfile(SendingProfile{
		Name: uniq("prof"), Host: "smtp.example.com", Port: 587,
		Username: "u", Password: "SuperSecret密码", TLSMode: "starttls",
	})
	if err != nil {
		t.Fatalf("upsert profile: %v", err)
	}
	got, err := s.GetSendingProfile(pid)
	if err != nil {
		t.Fatalf("get profile: %v", err)
	}
	if got.Password != "SuperSecret密码" {
		t.Fatalf("password roundtrip mismatch: %q", got.Password)
	}
}

func TestSQLiteStore(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	s.SetSecretKey(key)
	exercise(t, s)
}

func TestMySQLStore(t *testing.T) {
	// Set PHISH_TEST_MYSQL_DSN to run this against a disposable MySQL schema.
	dsn := os.Getenv("PHISH_TEST_MYSQL_DSN")
	if dsn == "" {
		dsn = "phish:change-me@tcp(127.0.0.1:3306)/phishsim_test?charset=utf8mb4"
	}
	s, err := OpenMySQL(dsn)
	if err != nil {
		t.Skipf("mysql unavailable: %v", err)
	}
	defer s.Close()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	s.SetSecretKey(key)
	exercise(t, s)
}

func TestTargetDepartmentRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "dept.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	gid, _ := s.CreateGroup("dept")
	if _, err := s.AddTargetsToGroup(gid, []Target{
		{Email: "a@example.com", FirstName: "A", Department: "研发部", Position: "工程师"},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListGroupTargets(gid)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Department != "研发部" || got[0].Position != "工程师" {
		t.Fatalf("unexpected target: %+v", got)
	}

	tpl, _ := s.UpsertTemplate(EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	page, _ := s.UpsertPage(LandingPage{Name: "p", Kind: "template", Body: "<p>x</p>"}, nil)
	camp, err := s.CreateCampaign(Campaign{Name: "c", EmailTemplateID: tpl, LandingPageID: page}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ListResults(camp)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Department != "研发部" {
		t.Fatalf("department not joined into results: %+v", res)
	}
}

func TestMigrateAddsDepartmentToOldSQLiteDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE targets(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		group_id INTEGER NOT NULL,
		email TEXT NOT NULL,
		first_name TEXT NOT NULL DEFAULT '',
		last_name TEXT NOT NULL DEFAULT '',
		position TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("migrate old db: %v", err)
	}
	defer s.Close()
	gid, _ := s.CreateGroup("old")
	if _, err := s.AddTargetsToGroup(gid, []Target{{Email: "a@example.com", Department: "财务部"}}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ListGroupTargets(gid)
	if len(got) != 1 || got[0].Department != "财务部" {
		t.Fatalf("unexpected targets: %+v", got)
	}
}
