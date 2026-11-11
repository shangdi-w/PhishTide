package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"phishsim/internal/core/config"
	"phishsim/internal/core/store"
)

const humanUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

func TestLandingFormCapturesArbitraryFields(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "landing.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SetSecretKey(make([]byte, 32))

	tid, err := st.UpsertTemplate(store.EmailTemplate{
		Name: "t", Subject: "s", HTML: "<p>{{.TrackingURL}}</p>", Text: "x",
	})
	if err != nil {
		t.Fatal(err)
	}
	// The built-in pages use the same placeholder; the server must rewrite it
	// to /l/<rid>/submit and capture every field the visitor fills in.
	pageID, err := st.UpsertPage(store.LandingPage{
		Name: "统一身份认证登录", Kind: "template",
		Body: `<form method="post" action="__SUBMIT_URL__">
<input name="username"><input name="password"><input name="otp"><input name="dept"></form>`,
		ContentType:        "text/html; charset=utf-8",
		CaptureCredentials: true,
		CapturePasswords:   true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := st.CreateGroup("g")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddTargetsToGroup(gid, []store.Target{{Email: "alice@example.com", FirstName: "Alice"}}); err != nil {
		t.Fatal(err)
	}
	campID, err := st.CreateCampaign(store.Campaign{
		Name: "c", EmailTemplateID: tid, LandingPageID: pageID,
	}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	results, err := st.ListResults(campID)
	if err != nil || len(results) != 1 {
		t.Fatalf("results: %v %d", err, len(results))
	}
	rid := results[0].Rid

	s := &Server{Cfg: &config.Config{PublicURL: "https://phish.example.com"}, Store: st}
	h := s.Handler()

	// 1. The email link opens the landing form with a per-target submit action.
	req := httptest.NewRequest(http.MethodGet, "/l/"+rid+"/", nil)
	req.Header.Set("User-Agent", humanUA)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("landing status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `action="/l/`+rid+`/submit"`) {
		t.Fatalf("form action not rewritten:\n%s", body)
	}
	if !strings.Contains(body, `name="otp"`) {
		t.Fatal("custom field missing from served form")
	}

	// 2. Submitting the form stores username/password and all extra fields.
	form := url.Values{
		"username": {"alice"},
		"password": {"s3cret!"},
		"otp":      {"123456"},
		"dept":     {"财务部"},
	}
	req = httptest.NewRequest(http.MethodPost, "/l/"+rid+"/submit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", humanUA)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusSeeOther {
		t.Fatalf("submit status %d: %s", rec.Code, rec.Body.String())
	}

	subs, err := st.ListSubmissions(campID)
	if err != nil || len(subs) != 1 {
		t.Fatalf("submissions: %v count=%d", err, len(subs))
	}
	sub := subs[0]
	if sub.Username != "alice" || sub.Password != "s3cret!" {
		t.Fatalf("captured credentials: user=%q pass=%q", sub.Username, sub.Password)
	}
	if got := strings.Join(sub.Fields["otp"], ","); got != "123456" {
		t.Fatalf("extra field otp=%q", got)
	}
	if got := strings.Join(sub.Fields["dept"], ","); got != "财务部" {
		t.Fatalf("extra field dept=%q", got)
	}
}

func TestCampaignRequiresLandingPage(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "campaign.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tid, err := st.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	if err != nil {
		t.Fatal(err)
	}
	gid, err := st.CreateGroup("g")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Cfg: &config.Config{}, Store: st}
	body := `{"name":"c","email_template_id":` + itoa64(tid) + `,"group_ids":[` + itoa64(gid) + `]}`
	req := httptest.NewRequest(http.MethodPost, "/__admin/api/campaigns", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.adminCreateCampaign(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "落地页") {
		t.Fatalf("campaign without landing page was accepted: %d %s", rec.Code, rec.Body.String())
	}
}

func itoa64(n int64) string {
	return strconv.FormatInt(n, 10)
}

func TestFailAttemptsPromptsThenRedirects(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "retry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tid, _ := st.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	pageID, err := st.UpsertPage(store.LandingPage{
		Name: "p", Kind: "template",
		Body:               `<html><body><form method="post" action="__SUBMIT_URL__"><input name="username"><input type="password" name="password"></form></body></html>`,
		ContentType:        "text/html; charset=utf-8",
		CaptureCredentials: true,
		CapturePasswords:   true,
		RedirectURL:        "https://portal.example.com/",
		ErrorMessage:       "用户名或密码错误，请重新输入",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gid, _ := st.CreateGroup("g")
	if _, err := st.AddTargetsToGroup(gid, []store.Target{{Email: "bob@example.com"}}); err != nil {
		t.Fatal(err)
	}
	campID, err := st.CreateCampaign(store.Campaign{Name: "c", EmailTemplateID: tid, LandingPageID: pageID}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	results, _ := st.ListResults(campID)
	if len(results) != 1 {
		t.Fatalf("results %d", len(results))
	}
	rid := results[0].Rid

	s := &Server{Cfg: &config.Config{PublicURL: "https://phish.example.com", FailAttempts: 2}, Store: st}
	h := s.Handler()

	post := func(pw string) *httptest.ResponseRecorder {
		form := url.Values{"username": {"bob@example.com"}, "password": {pw}}
		req := httptest.NewRequest(http.MethodPost, "/l/"+rid+"/submit", strings.NewReader(form.Encode()))
		req.Header.Set("User-Agent", humanUA)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	for i, pw := range []string{"first", "second"} {
		rec := post(pw)
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: status %d", i+1, rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "用户名或密码错误") || !strings.Contains(body, `data-hp-retry`) {
			t.Fatalf("attempt %d: no retry prompt:\n%s", i+1, body)
		}
	}
	rec := post("third")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("third attempt should redirect, got %d", rec.Code)
	}
	n, err := st.CountSubmissions(results[0].ID)
	if err != nil || n != 3 {
		t.Fatalf("captured %d submissions (%v), want 3", n, err)
	}
}
