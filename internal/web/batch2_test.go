package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"phishsim/internal/core/config"
	"phishsim/internal/core/store"
)

func TestLinkExpiredPolicy(t *testing.T) {
	now := time.Now().UTC()
	fresh := now.Add(-30 * time.Minute).Format(time.RFC3339Nano)
	old := now.Add(-3 * time.Hour).Format(time.RFC3339Nano)

	if linkExpired(store.Campaign{}, store.Result{SentAt: old}) {
		t.Fatal("no policy must never expire")
	}
	if !linkExpired(store.Campaign{LinkTTLHours: 2}, store.Result{SentAt: old}) {
		t.Fatal("TTL 2h should reject a 3h-old link")
	}
	if linkExpired(store.Campaign{LinkTTLHours: 2}, store.Result{SentAt: fresh}) {
		t.Fatal("TTL 2h should accept a 30m-old link")
	}
	if !linkExpired(store.Campaign{LinkOnce: true}, store.Result{Submitted: true}) {
		t.Fatal("one-time link should reject after submit")
	}
	if linkExpired(store.Campaign{LinkOnce: true}, store.Result{Opened: true}) {
		t.Fatal("one-time link should stay alive before submit")
	}
	// A malformed timestamp must not block the link.
	if linkExpired(store.Campaign{LinkTTLHours: 1}, store.Result{SentAt: "not-a-time"}) {
		t.Fatal("malformed sent_at should not expire the link")
	}
}

func TestLinkIPPolicy(t *testing.T) {
	camp := store.Campaign{IPDeny: "10.0.0.0/8, 192.0.2.9", IPAllow: "203.0.113.0/24, 198.51.100.7"}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"192.0.2.9", true},
		{"203.0.113.5", false},
		{"198.51.100.7", false},
		{"8.8.8.8", true}, // not in allow list
		{"", false},
	}
	for _, c := range cases {
		if got := linkIPBlocked(camp, c.ip); got != c.want {
			t.Fatalf("linkIPBlocked(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
	// Empty allow list means "no allow restriction".
	if linkIPBlocked(store.Campaign{IPDeny: "192.0.2.1"}, "203.0.113.9") {
		t.Fatal("deny-only list blocked an unrelated IP")
	}
	if got := invalidIPList("10.0.0.0/8, nope, 1.2.3.4.5, 192.0.2.1"); strings.Join(got, "|") != "nope|1.2.3.4.5" {
		t.Fatalf("invalidIPList = %v", got)
	}
}

func TestSplitSeedEmails(t *testing.T) {
	got := splitSeedEmails("a@example.com, b@example.com\nA@example.com; c@x")
	if strings.Join(got, "|") != "a@example.com|b@example.com|c@x" {
		t.Fatalf("seeds = %v", got)
	}
	if bad := invalidSeedList("a@example.com, nope, x@y@z"); strings.Join(bad, "|") != "nope|x@y@z" {
		t.Fatalf("invalid seeds = %v", bad)
	}
}

func TestCampaignABVariantAssignmentAndSelection(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/ab.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SetSecretKey(make([]byte, 32))

	tplA, _ := st.UpsertTemplate(store.EmailTemplate{Name: "A", Subject: "A-subject", HTML: "<p>A</p>"})
	tplB, _ := st.UpsertTemplate(store.EmailTemplate{Name: "B", Subject: "B-subject", HTML: "<p>B</p>"})
	page, _ := st.UpsertPage(store.LandingPage{Name: "p", Kind: "template", Body: "<p>x</p>"}, nil)
	gid, _ := st.CreateGroup("g")
	var targets []store.Target
	for i := 0; i < 40; i++ {
		targets = append(targets, store.Target{Email: fmt.Sprintf("u%d@example.com", i)})
	}
	if _, err := st.AddTargetsToGroup(gid, targets); err != nil {
		t.Fatal(err)
	}

	// 50/50: both variants appear, and the campaign keeps the policy fields.
	campID, err := st.CreateCampaign(store.Campaign{
		Name: "ab", EmailTemplateID: tplA, EmailTemplateBID: tplB, ABSplit: 50, LandingPageID: page,
		LinkTTLHours: 12, LinkOnce: true, IPAllow: "203.0.113.0/24", IPDeny: "10.0.0.0/8",
		SeedEmails: "seed@example.com",
	}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	camp, _ := st.GetCampaign(campID)
	if camp.EmailTemplateBID != tplB || camp.ABSplit != 50 || camp.LinkTTLHours != 12 || !camp.LinkOnce ||
		camp.IPAllow != "203.0.113.0/24" || camp.IPDeny != "10.0.0.0/8" || camp.SeedEmails != "seed@example.com" {
		t.Fatalf("campaign policy did not round-trip: %+v", camp)
	}
	results, _ := st.ListResults(campID)
	countB := 0
	for _, r := range results {
		if r.Variant == "B" {
			countB++
		} else if r.Variant != "A" {
			t.Fatalf("unexpected variant %q", r.Variant)
		}
	}
	if countB == 0 || countB == len(results) {
		t.Fatalf("50/50 split produced %d/%d B", countB, len(results))
	}

	// Split 100 = all A, split 0 = all B; dry-run preview subject must match.
	s := &Server{Cfg: &config.Config{PublicURL: "https://phish.example.com"}, Store: st}
	for _, split := range []int{100, 0} {
		id, err := st.CreateCampaign(store.Campaign{
			Name: fmt.Sprintf("split-%d", split), EmailTemplateID: tplA, EmailTemplateBID: tplB,
			ABSplit: split, LandingPageID: page,
		}, []int64{gid})
		if err != nil {
			t.Fatal(err)
		}
		out, err := s.sendCampaignEmail(id, 0, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		wantVariant, wantSubject := "A", "A-subject"
		if split == 0 {
			wantVariant, wantSubject = "B", "B-subject"
		}
		if len(out.Previews) == 0 {
			t.Fatalf("split %d produced no previews", split)
		}
		for _, p := range out.Previews {
			if p["variant"] != wantVariant || p["subject"] != wantSubject {
				t.Fatalf("split %d preview = %+v", split, p)
			}
		}
	}
}

func TestLandingOnceAndIPFilter(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/policy.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SetSecretKey(make([]byte, 32))

	tid, _ := st.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	page, _ := st.UpsertPage(store.LandingPage{
		Name: "p", Kind: "template",
		Body:               `<form method="post" action="__SUBMIT_URL__"><input name="username"></form>`,
		CaptureCredentials: true,
	}, nil)
	gid, _ := st.CreateGroup("g")
	_, _ = st.AddTargetsToGroup(gid, []store.Target{{Email: "alice@example.com"}})
	campID, err := st.CreateCampaign(store.Campaign{
		Name: "c", EmailTemplateID: tid, LandingPageID: page,
		LinkOnce: true, IPDeny: "192.0.2.0/24",
	}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	results, _ := st.ListResults(campID)
	rid := results[0].Rid

	s := &Server{Cfg: &config.Config{PublicURL: "https://phish.example.com"}, Store: st}
	h := s.Handler()

	get := func(remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/l/"+rid+"/", nil)
		req.RemoteAddr = remote
		req.Header.Set("User-Agent", humanUA)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := get("192.0.2.5:443"); rec.Code != http.StatusForbidden {
		t.Fatalf("denied IP got %d", rec.Code)
	}
	if rec := get("198.51.100.7:443"); rec.Code != http.StatusOK {
		t.Fatalf("allowed IP got %d: %s", rec.Code, rec.Body.String())
	}

	// Submit once, then the one-time link is burned.
	form := url.Values{"username": {"alice"}}
	req := httptest.NewRequest(http.MethodPost, "/l/"+rid+"/submit", strings.NewReader(form.Encode()))
	req.RemoteAddr = "198.51.100.7:443"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", humanUA)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusSeeOther {
		t.Fatalf("submit got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := get("198.51.100.7:443"); rec.Code != http.StatusGone {
		t.Fatalf("burned link got %d, want 410", rec.Code)
	}
}

func TestSeedDeliveryUsesATemplate(t *testing.T) {
	host, port, got := startSMTPSink(t)
	s := newAgentServer(t)
	tplA, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "A", Subject: "seed-A", HTML: "<p>A</p>", Text: "A"})
	tplB, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "B", Subject: "seed-B", HTML: "<p>B</p>", Text: "B"})
	page, _ := s.Store.UpsertPage(store.LandingPage{Name: "p", Kind: "template", Body: "<p>x</p>"}, nil)
	gid, _ := s.Store.CreateGroup("g")
	_, _ = s.Store.AddTargetsToGroup(gid, []store.Target{{Email: "victim@example.com"}})
	prof, err := s.Store.UpsertSendingProfile(store.SendingProfile{
		Name: "sink", Host: host, Port: port, TLSMode: "none", FromEmail: "ops@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	camp, err := s.Store.CreateCampaign(store.Campaign{
		Name: "seeds", EmailTemplateID: tplA, EmailTemplateBID: tplB, ABSplit: 0,
		LandingPageID: page, SendingProfileID: prof, SeedEmails: "seed1@example.com\nseed2@example.com",
	}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.sendCampaignEmail(camp, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if out.Sent != 1 || out.Seeds != 2 || out.Failed != 0 {
		t.Fatalf("outcome = %+v", out)
	}
	var mails []string
	for i := 0; i < 3; i++ {
		select {
		case m := <-got:
			mails = append(mails, m)
		case <-time.After(3 * time.Second):
			t.Fatalf("received %d of 3 mails", len(mails))
		}
	}
	seedMails := 0
	for _, m := range mails {
		if strings.Contains(m, "To: seed") {
			seedMails++
			if !strings.Contains(m, "seed-A") {
				t.Fatalf("seed got the wrong template: %s", m)
			}
		}
	}
	if seedMails != 2 {
		t.Fatalf("seed mails = %d, all mails = %d", seedMails, len(mails))
	}
}
