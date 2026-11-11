package web

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"phishsim/internal/core/store"
)

const proxyHumanUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"

// proxyUpstream is a tiny fake login site with an absolute-path bundle, an API
// call, a cookie-setting redirect and a form POST target.
type proxyUpstream struct {
	srv        *httptest.Server
	loginPosts atomic.Int32
	saveBodies chan string
}

func newProxyUpstream(t *testing.T) *proxyUpstream {
	t.Helper()
	u := &proxyUpstream{saveBodies: make(chan string, 4)}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			u.loginPosts.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"upstream":"real-login"}`))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
<link rel="stylesheet" href="/style.css">
<script src="/static/app.js"></script></head>
<body><h1>Sign in</h1>
<form method="post" action="/login"><input name="username"><input name="password" type="password"><button>登录</button></form>
<img src="/img/logo.png">
</body></html>`)
	})
	mux.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write([]byte(`body{background:url(/img/bg.png)}`))
	})
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`fetch('/api/save')`))
	})
	mux.HandleFunc("/api/save", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		select {
		case u.saveBodies <- string(b):
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"saved":true}`))
	})
	mux.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", Path: "/", Domain: "sso.example.com", HttpOnly: true})
		http.Redirect(w, r, "/login", http.StatusFound)
	})
	u.srv = httptest.NewServer(mux)
	t.Cleanup(u.srv.Close)
	return u
}

// proxyCampaign creates a proxy landing page plus a campaign/target so the
// landing handler (which keys on the result rid) can be exercised.
func proxyCampaign(t *testing.T, s *Server, source string) (int64, int64, store.Result) {
	t.Helper()
	pid, err := s.Store.UpsertPage(store.LandingPage{
		Name: "proxy-cn", Kind: "proxy", SourceURL: source,
		ContentType:        "text/html; charset=utf-8",
		CaptureCredentials: true, CapturePasswords: true,
		RedirectURL: "https://company.example/done",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tpl, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	gid, _ := s.Store.CreateGroup("g")
	if _, err := s.Store.AddTargetsToGroup(gid, []store.Target{{Email: "victim@example.com"}}); err != nil {
		t.Fatal(err)
	}
	cid, err := s.Store.CreateCampaign(store.Campaign{Name: "c", EmailTemplateID: tpl, LandingPageID: pid}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	results, _ := s.Store.ListResults(cid)
	if len(results) != 1 {
		t.Fatalf("results = %d", len(results))
	}
	s.Store.MarkSent(results[0].ID)
	return pid, cid, results[0]
}

func doLanding(t *testing.T, s *Server, method, path, body, contentType string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("User-Agent", proxyHumanUA)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	s.landing(rr, req)
	return rr
}

func TestProxyLandingRedirectsToLivePath(t *testing.T) {
	s := newAgentServer(t)
	up := newProxyUpstream(t)
	_, _, res := proxyCampaign(t, s, up.srv.URL+"/login")

	rr := doLanding(t, s, http.MethodGet, "/l/"+res.Rid+"/", "", "", nil)
	if rr.Code != http.StatusFound {
		t.Fatalf("root = %d, want 302 (%s)", rr.Code, rr.Body.String())
	}
	want := "/l/" + res.Rid + "/px/login"
	if got := rr.Header().Get("Location"); got != want {
		t.Fatalf("Location = %q want %q", got, want)
	}
}

func TestProxyServesRewrittenDocumentAndAssets(t *testing.T) {
	s := newAgentServer(t)
	up := newProxyUpstream(t)
	_, _, res := proxyCampaign(t, s, up.srv.URL+"/login")
	root := "/l/" + res.Rid + "/px/"

	rr := doLanding(t, s, http.MethodGet, root+"login", "", "", nil)
	if rr.Code != 200 {
		t.Fatalf("document = %d %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		`href="` + root + `style.css"`,
		`src="` + root + `static/app.js"`,
		`action="` + root + `login"`,
		`src="` + root + `img/logo.png"`,
		`data-hp-proxy="1"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("document missing %q\n%s", want, body)
		}
	}
	if strings.Contains(body, "Content-Security-Policy") {
		t.Errorf("upstream CSP was not stripped")
	}
	if !strings.Contains(body, `var rid="`+res.Rid+`"`) {
		t.Errorf("beacon not injected")
	}

	rr = doLanding(t, s, http.MethodGet, root+"style.css", "", "", nil)
	if !strings.Contains(rr.Body.String(), `url("`+root+`img/bg.png")`) {
		t.Fatalf("stylesheet not rewritten: %s", rr.Body.String())
	}

	rr = doLanding(t, s, http.MethodGet, root+"static/app.js", "", "", nil)
	if !strings.HasPrefix(rr.Header().Get("Content-Type"), "application/javascript") {
		t.Fatalf("js content-type = %q", rr.Header().Get("Content-Type"))
	}
}

func TestProxyCapturesPasswordWithoutHittingUpstream(t *testing.T) {
	s := newAgentServer(t)
	up := newProxyUpstream(t)
	_, cid, res := proxyCampaign(t, s, up.srv.URL+"/login")
	root := "/l/" + res.Rid + "/px/"

	form := url.Values{"username": {"victim@example.com"}, "password": {"S3cret!"}}
	rr := doLanding(t, s, http.MethodPost, root+"login", form.Encode(),
		"application/x-www-form-urlencoded", map[string]string{"X-Requested-With": "XMLHttpRequest"})
	if rr.Code != 200 {
		t.Fatalf("capture response = %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"ok":true`) {
		t.Fatalf("expected fake success JSON, got %s", rr.Body.String())
	}
	if n := up.loginPosts.Load(); n != 0 {
		t.Fatalf("password POST was forwarded upstream %d times", n)
	}
	subs, err := s.Store.ListSubmissions(cid)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 || subs[0].Username != "victim@example.com" || subs[0].Password != "S3cret!" {
		t.Fatalf("submissions = %+v", subs)
	}

	// The campaign's results must show the submission.
	results, _ := s.Store.ListResults(cid)
	if len(results) != 1 || !results[0].Submitted {
		t.Fatalf("result not marked submitted: %+v", results)
	}
}

func TestProxyForwardsNonCredentialTraffic(t *testing.T) {
	s := newAgentServer(t)
	up := newProxyUpstream(t)
	_, _, res := proxyCampaign(t, s, up.srv.URL+"/login")
	root := "/l/" + res.Rid + "/px/"

	rr := doLanding(t, s, http.MethodPost, root+"api/save", `{"item":7}`,
		"application/json", map[string]string{"Accept": "application/json"})
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"saved":true`) {
		t.Fatalf("forward = %d %s", rr.Code, rr.Body.String())
	}
	select {
	case got := <-up.saveBodies:
		if got != `{"item":7}` {
			t.Fatalf("upstream body = %q", got)
		}
	default:
		t.Fatal("request was not forwarded upstream")
	}
}

func TestProxyRewritesRedirectAndCookieScope(t *testing.T) {
	s := newAgentServer(t)
	up := newProxyUpstream(t)
	_, _, res := proxyCampaign(t, s, up.srv.URL+"/login")
	root := "/l/" + res.Rid + "/px/"

	rr := doLanding(t, s, http.MethodGet, root+"set", "", "", nil)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != root+"login" {
		t.Fatalf("Location = %q want %q", loc, root+"login")
	}
	cookies := rr.Header().Values("Set-Cookie")
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie = %v", cookies)
	}
	if !strings.Contains(cookies[0], "Path="+root) || strings.Contains(cookies[0], "Domain=") {
		t.Fatalf("cookie not re-scoped: %q", cookies[0])
	}
}

func TestProxyCredentialFieldsJSONAndMultipart(t *testing.T) {
	fields := proxyCredentialFields("application/json", []byte(`{"user":{"name":"u"},"auth":{"password":"p"},"remember":true}`))
	if got := pickField(fields, "password"); got != "p" {
		t.Fatalf("nested json password = %q fields=%v", got, fields)
	}
	body := "--X\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\npw123\r\n--X--\r\n"
	fields = proxyCredentialFields("multipart/form-data; boundary=X", []byte(body))
	if got := pickField(fields, "password"); got != "pw123" {
		t.Fatalf("multipart password = %q fields=%v", got, fields)
	}
}

func TestProxyPageSkipsStaticValidationAndE2EBrowser(t *testing.T) {
	s := newAgentServer(t)
	p := store.LandingPage{ID: 3, Name: "px", Kind: "proxy", SourceURL: "https://sso.example.com/login"}
	if check := checkLandingPage(p); !check.OK {
		t.Fatalf("proxy page failed static check: %+v", check)
	}
	broken := store.LandingPage{ID: 4, Name: "px2", Kind: "proxy"}
	if check := checkLandingPage(broken); check.OK {
		t.Fatalf("proxy page without source_url should fail")
	}
	out := s.e2eCheckPage(p)
	if !out.OK || out.Skipped == "" && len(out.Warnings) == 0 {
		t.Fatalf("e2e result = %+v", out)
	}
}
