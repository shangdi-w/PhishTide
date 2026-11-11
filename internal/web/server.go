// Package web implements the phishing portal: per-target landing pages, email
// tracking, the report-phishing endpoint, behavior beacons, credential/form
// capture, and the operator admin backend.
package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"phishsim/internal/core/config"
	"phishsim/internal/core/logbuf"
	"phishsim/internal/core/store"
	"phishsim/internal/features/llm"
	"phishsim/internal/services/detect"
	"phishsim/internal/services/geoip"
)

//go:embed static/admin.html static/vendor/*
var staticFS embed.FS

// Server wires the HTTP surface to the store and configuration.
type Server struct {
	Cfg       *config.Config
	Store     *store.Store
	LLM       *llm.Client
	Log       *slog.Logger
	LogBuffer *logbuf.Buffer

	// Geo is the optional offline IP-to-country database. Nil means no
	// enrichment: the platform never performs active geo lookups.
	Geo *geoip.DB

	llmMu sync.Mutex // guards runtime LLM config swaps

	// Runtime settings (brand, console password hash, background) cached from
	// the app_settings table.
	settingsMu     sync.RWMutex
	settingsCache  appSettings
	settingsLoaded bool

	// SessionKey signs console cookies. main sets it to the at-rest AES key so
	// sessions survive restarts and cannot be forged without the key file.
	SessionKey []byte

	loginLimiter loginLimiter

	trustOnce   sync.Once
	trustedNets []*net.IPNet

	// llmRate holds one one-minute window per console session (or client IP
	// when no session cookie is present), so several operators do not share a
	// single budget.
	llmRate struct {
		mu      sync.Mutex
		windows map[string]*llmRateWindow
	}

	// confirms holds send requests the assistant prepared and is waiting for
	// the operator to approve. Keyed by a random id; they expire.
	confirmMu sync.Mutex
	confirms  map[string]*pendingConfirm

	// guard tracks prompt-injection taint, approved plans and per-turn write
	// counts for the console assistant.
	guard struct {
		mu           sync.Mutex
		tainted      map[int64]bool
		plan         map[int64]bool
		writes       map[int64]int
		approveUntil map[int64]time.Time
	}

	// Background agent job queue (see agentjobs.go).
	jobStart    sync.Once
	jobCh       chan int64
	jobMu       sync.Mutex
	jobQueued   map[int64]bool
	jobCancelMu sync.Mutex
	jobCancels  map[int64]context.CancelFunc

	// uploadSent marks attachments already injected into a model turn, so a
	// long conversation does not re-send the same image/PDF text every turn.
	uploadMu   sync.Mutex
	uploadSent map[int64]bool

	// runMu serialises agent runs per conversation: an interactive turn and a
	// background job must not interleave history/tool writes.
	runMu           sync.Mutex
	runningSessions map[int64]bool

	// actions holds overwrite requests the assistant prepared (overwriting an
	// existing template/page/profile by name) and waits for operator approval.
	actionMu sync.Mutex
	actions  map[string]*pendingAction

	// bounceMu serialises IMAP polls; lastBouncePoll throttles the automatic
	// poller so a configured mailbox is checked a few times an hour, not on
	// every scheduler tick.
	bounceMu       sync.Mutex
	lastBouncePoll time.Time
}

type llmRateWindow struct {
	start time.Time
	count int
}

// llmRateKey identifies the caller: the console session cookie when present,
// otherwise a bearer key or the client IP.
func llmRateKey(r *http.Request) string {
	raw := ""
	if c, err := r.Cookie("phish_admin"); err == nil && c.Value != "" {
		raw = "s:" + c.Value
	} else if h := r.Header.Get("Authorization"); h != "" {
		raw = "a:" + h
	} else {
		host := r.RemoteAddr
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		raw = "ip:" + host
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:8])
}

// allowLLMCall enforces a calls-per-minute window per caller.
func (s *Server) allowLLMCall(r *http.Request, ratePerMin int) bool {
	if ratePerMin <= 0 {
		return true
	}
	key := llmRateKey(r)
	now := time.Now()
	s.llmRate.mu.Lock()
	defer s.llmRate.mu.Unlock()
	if s.llmRate.windows == nil {
		s.llmRate.windows = make(map[string]*llmRateWindow)
	}
	// Bound the map: drop expired windows once it grows.
	if len(s.llmRate.windows) > 256 {
		for k, w := range s.llmRate.windows {
			if now.Sub(w.start) >= time.Minute {
				delete(s.llmRate.windows, k)
			}
		}
	}
	w := s.llmRate.windows[key]
	if w == nil || now.Sub(w.start) >= time.Minute {
		w = &llmRateWindow{start: now}
		s.llmRate.windows[key] = w
	}
	if w.count >= ratePerMin {
		return false
	}
	w.count++
	return true
}

func (s *Server) getLLM() *llm.Client {
	s.llmMu.Lock()
	defer s.llmMu.Unlock()
	return s.LLM
}

func (s *Server) setLLM(c *llm.Client) {
	s.llmMu.Lock()
	s.LLM = c
	s.llmMu.Unlock()
}

// Handler returns the root http.Handler.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			s.log().Error("panic", "err", rec, "path", r.URL.Path)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}()
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

	switch {
	case r.URL.Path == "/metrics":
		s.handleMetrics(w, r)
	case strings.HasPrefix(r.URL.Path, "/__admin"):
		s.admin(w, r)
	case strings.HasPrefix(r.URL.Path, "/b/"):
		s.behavior(w, r)
	case strings.HasPrefix(r.URL.Path, "/t/"):
		s.track(w, r)
	case strings.HasPrefix(r.URL.Path, "/r/"):
		s.report(w, r)
	case strings.HasPrefix(r.URL.Path, "/u/"):
		s.unsubscribe(w, r)
	case strings.HasPrefix(r.URL.Path, "/l/"):
		s.landing(w, r)
	case strings.HasPrefix(r.URL.Path, "/p/"):
		s.preview(w, r)
	case strings.HasPrefix(r.URL.Path, "/vendor/"):
		s.serveStatic(w, r, "static"+r.URL.Path)
	case r.URL.Path == "/assets/background":
		s.serveBackground(w, r)
	case r.URL.Path == "/favicon.ico":
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/":
		if s.Cfg.RootRedirect {
			http.Redirect(w, r, "/__admin", http.StatusFound)
			return
		}
		s.notFound(w)
	default:
		s.notFound(w)
	}
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// ---------------------------------------------------------------------------
// Tracking pixel

func (s *Server) track(w http.ResponseWriter, r *http.Request) {
	rid := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/t/"), ".gif")
	res, err := s.Store.ResultByRid(strings.TrimSpace(rid))
	if err != nil {
		s.writeGIF(w)
		return
	}
	// Do not count sandbox/crawler opens: they inflate the open rate.
	if detect.Classify(r.UserAgent()) == detect.Human {
		s.Store.MarkOpened(res, s.remoteIP(r), r.UserAgent(), r.Header.Get("Referer"))
	}
	s.writeGIF(w)
}

// ---------------------------------------------------------------------------
// Report phishing

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	rid := strings.TrimPrefix(r.URL.Path, "/r/")
	res, err := s.Store.ResultByRid(strings.TrimSpace(rid))
	if err != nil {
		s.notFound(w)
		return
	}
	s.Store.MarkReported(res, s.remoteIP(r), r.UserAgent(), r.Header.Get("Referer"))
	s.log().Info("phishing reported", "campaign", res.CampaignID, "email", res.Email, "ip", s.remoteIP(r))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(reportedPage))
}

// unsubscribe marks a target as having unsubscribed from the campaign.
func (s *Server) unsubscribe(w http.ResponseWriter, r *http.Request) {
	rid := strings.TrimPrefix(r.URL.Path, "/u/")
	res, err := s.Store.ResultByRid(strings.TrimSpace(rid))
	if err != nil {
		s.notFound(w)
		return
	}
	_ = s.Store.Unsubscribe(strings.TrimSpace(rid))
	if res.Email != "" {
		_ = s.Store.UpsertSuppression(res.Email, "unsubscribe", "退订链接")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(unsubscribedPage))
}

// ---------------------------------------------------------------------------
// Behavior beacon

func (s *Server) behavior(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/b/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rid := parts[0]
	if len(rid) > 128 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	kind := "page_load"
	if len(parts) > 1 && parts[1] != "" {
		kind = truncate(parts[1], 64)
	}
	detail := truncate(r.URL.Query().Get("d"), 1024)
	s.Store.RecordBehavior(rid, kind, detail, s.remoteIP(r), r.UserAgent())
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Landing page + capture

func (s *Server) landing(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/l/")
	parts := strings.SplitN(rest, "/", 3)
	rid := parts[0]

	res, err := s.Store.ResultByRid(rid)
	if err != nil {
		s.notFound(w)
		return
	}
	camp, err := s.Store.GetCampaign(res.CampaignID)
	if err != nil {
		s.notFound(w)
		return
	}
	page, err := s.Store.GetPage(camp.LandingPageID)
	if err != nil {
		s.notFound(w)
		return
	}

	// Campaign access policy: IP allow/deny, link lifetime, burn-after-submit.
	if linkIPBlocked(camp, s.remoteIP(r)) {
		s.serveHTMLStatus(w, http.StatusForbidden, blockedPage)
		return
	}
	if linkExpired(camp, res) {
		s.serveHTMLStatus(w, http.StatusGone, expiredPage)
		return
	}

	// Asset request: /l/<rid>/assets/<hash>/<name...>
	if len(parts) >= 3 && parts[1] == "assets" {
		s.serveAsset(w, r, page.ID, parts[2])
		return
	}

	// Form submission (accepts both POST and GET form methods).
	if len(parts) >= 2 && parts[1] == "submit" && (r.Method == http.MethodPost || r.Method == http.MethodGet) {
		s.capture(w, r, res, page, camp)
		return
	}

	// A terminated campaign no longer serves the phish.
	if camp.Status == "terminated" {
		s.serveHTML(w, terminatedPage)
		return
	}
	// Non-human visitors (crawlers, sandboxes, scanners) get a harmless page and
	// are not counted as clicks.
	if detect.Classify(r.UserAgent()) != detect.Human {
		s.serveHTML(w, benignPage)
		return
	}

	// A reverse-proxy page forwards the live upstream site (and its API) through
	// the portal instead of serving a stored snapshot.
	if page.Kind == "proxy" {
		s.serveProxy(w, r, page, &res, &camp, "/l/"+rid)
		return
	}

	s.Store.MarkClicked(res, s.remoteIP(r), r.UserAgent(), r.Header.Get("Referer"))
	body := renderLanding(page.Body, "/l/"+rid)
	body = injectBeacon(body, rid)
	body = injectMobileCompat(body)
	s.serveHTML(w, body)
}

func (s *Server) serveAsset(w http.ResponseWriter, r *http.Request, pageID int64, sub string) {
	assetPath := "/__assets__/" + sub
	a, err := s.Store.GetAsset(pageID, assetPath)
	if err != nil {
		s.notFound(w)
		return
	}
	ct := a.ContentType
	if ct == "" {
		ct = mime.TypeByExtension(path.Ext(sub))
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(200)
	_, _ = w.Write(a.Body)
}

func (s *Server) serveHTML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(body))
}

// renderLanding rewrites the per-target placeholders in a landing page body,
// mapping the form action and mirrored assets under the given URL prefix.
func renderLanding(body, prefix string) string {
	submit := prefix + "/submit"
	asset := prefix + "/assets/"
	body = strings.ReplaceAll(body, "__SUBMIT_URL__", submit)
	body = strings.ReplaceAll(body, "/__submit__", submit)
	body = strings.ReplaceAll(body, "/__assets__/", asset)
	return body
}

// preview serves a landing page (and its mirrored assets) directly by page id,
// so an operator can inspect a cloned site without creating a campaign. The
// submit action redirects to the page's redirect URL but captures nothing.
func (s *Server) preview(w http.ResponseWriter, r *http.Request) {
	// Preview pages are operator-only: page ids are sequential, so leaving this
	// public would let anyone enumerate cloned landing pages.
	if !s.sessionFromRequest(r, adminPreviewName) && !s.adminAuthorized(r) {
		s.notFound(w)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/p/")
	parts := strings.SplitN(rest, "/", 2)
	id := parseInt(parts[0])
	if id <= 0 {
		s.notFound(w)
		return
	}
	page, err := s.Store.GetPage(id)
	if err != nil {
		s.notFound(w)
		return
	}
	prefix := "/p/" + strconv.FormatInt(id, 10)

	// A preview renders untrusted cloned markup in the same origin as the
	// operator console. Sandbox it and block scripts so a malicious cloned page
	// cannot call /__admin APIs with the operator's cookies.
	const previewCSP = "sandbox; default-src * data: blob:; script-src 'none'; " +
		"object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	w.Header().Set("Content-Security-Policy", previewCSP)

	if len(parts) == 2 && strings.HasPrefix(parts[1], "assets/") {
		// A directly opened asset is a document too, so it carries its own CSP.
		w.Header().Set("Content-Security-Policy", "sandbox")
		s.serveAsset(w, r, page.ID, strings.TrimPrefix(parts[1], "assets/"))
		return
	}
	if len(parts) == 2 && parts[1] == "submit" && r.Method == http.MethodPost {
		s.redirect(w, r, page.RedirectURL)
		return
	}
	// Proxy pages render the live upstream site; a preview never captures.
	if page.Kind == "proxy" {
		s.serveProxy(w, r, page, nil, nil, prefix)
		return
	}

	body := renderLanding(page.Body, prefix)
	body = injectMobileCompat(body)
	ct := page.ContentType
	if ct == "" {
		ct = "text/html; charset=utf-8"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(200)
	_, _ = w.Write([]byte(body))
}

// injectBeacon appends the behavior-tracking script before </body>.
func injectBeacon(body, rid string) string {
	js := strings.ReplaceAll(beaconJS, "__RID__", rid)
	js = strings.ReplaceAll(js, "__BASE__", "")
	idx := strings.LastIndex(strings.ToLower(body), "</body>")
	if idx < 0 {
		return body + "<script>" + js + "</script>"
	}
	return body[:idx] + "<script>" + js + "</script>" + body[idx:]
}

// capture records one form submission and redirects the victim. It honours the
// landing page's capture toggles, skips non-human visitors and terminated
// campaigns, and ignores a fully empty submission.
func (s *Server) capture(w http.ResponseWriter, r *http.Request, res store.Result, page store.LandingPage, camp store.Campaign) {
	if camp.Status == "terminated" || detect.Classify(r.UserAgent()) != detect.Human {
		s.redirect(w, r, page.RedirectURL)
		return
	}
	// Reject cross-site submissions so a third party cannot poison captured
	// data with forged credentials. Requests without Origin/Referer (curl,
	// email clients) are still accepted.
	if crossSite(r) {
		s.redirect(w, r, page.RedirectURL)
		return
	}
	fields, username, password := s.parseSubmission(w, r)

	if !page.CaptureCredentials {
		s.redirect(w, r, page.RedirectURL)
		return
	}
	if !page.CapturePasswords {
		password = ""
		blankPasswords(fields)
	}
	if username == "" && password == "" && !hasAnyValue(fields) {
		s.redirect(w, r, page.RedirectURL)
		return
	}

	// FailAttempts makes the page reject the first N logins with a generic
	// "wrong password" prompt so the visitor types it again. Each submission is
	// still stored, so every password variant is captured.
	attempts, _ := s.Store.CountSubmissions(res.ID)
	attempt := attempts + 1

	if err := s.Store.RecordSubmission(res, s.remoteIP(r), r.UserAgent(), r.Header.Get("Referer"), username, password, fields); err != nil {
		s.log().Error("record submission", "err", err)
	}
	s.log().Info("credential submitted",
		"campaign", res.CampaignID, "email", res.Email, "has_username", username != "", "attempt", attempt, "ip", s.remoteIP(r))

	if s.Cfg.FailAttempts > 0 && attempt <= s.Cfg.FailAttempts {
		body := renderRetry(page.Body, "/l/"+res.Rid, username, retryMessage(page))
		s.serveHTML(w, body)
		return
	}
	s.redirect(w, r, page.RedirectURL)
}

// renderRetry re-serves the landing page with a "wrong password" banner and
// the previous username prefilled, which is what a real login form does after
// a failed attempt. The banner text comes from the page so it matches the
// page's language and brand.
func renderRetry(body, prefix, username, errorMessage string) string {
	body = renderLanding(body, prefix)
	msg := strings.TrimSpace(errorMessage)
	if msg == "" {
		msg = "用户名或密码错误，请重新输入"
	}
	banner := `<div data-hp-retry="1" style="position:fixed!important;top:0!important;left:0!important;right:0!important;` +
		`z-index:2147483647!important;background:#fef2f2!important;border-bottom:1px solid #fecaca!important;` +
		`color:#b91c1c!important;font:14px/1.5 -apple-system,system-ui,sans-serif!important;padding:10px 14px!important;` +
		`text-align:center!important;box-sizing:border-box!important;margin:0!important">` + html.EscapeString(msg) + `</div>`
	u, _ := json.Marshal(username)
	script := `<script data-hp-retry="1">(function(){function p(){try{var v=` + string(u) + `;var ins=document.querySelectorAll('input');` +
		`var t=null,pw=null;for(var i=0;i<ins.length;i++){var el=ins[i],ty=(el.type||'text').toLowerCase();` +
		`if(!el.offsetWidth)continue;if(ty==='password'){if(!pw)pw=el;continue}` +
		`if((ty==='text'||ty==='email'||ty==='tel')&&!t)t=el}` +
		`if(t&&v&&!t.value)t.value=v;if(pw){pw.value='';pw.focus()}}catch(e){}}` +
		`setTimeout(p,120);window.addEventListener('load',p)})();</script>`
	return injectMobileCompat(injectBeforeBodyEnd(injectAfterBodyStart(body, banner), script))
}

// mobileCompatCSS rescues cloned pages that were captured from a desktop
// render: their layout often carries inline pixel geometry (wide containers,
// large margin-left) that pushes the login form off a phone screen. The rules
// only apply below 820px, so desktop rendering is unchanged, and they also
// stop iOS Safari from zooming into 14px inputs on focus.
const mobileCompatCSS = `<style data-hp-mobile-compat="1">
@media (max-width:820px){
html,body{width:100%!important;overflow-x:hidden!important}
body *{max-width:100vw!important}
div[style*="margin-left"]{margin-left:0!important}
div[style*="right:"]{right:auto!important}
input,textarea,select{font-size:16px!important}
img,video{max-width:100%!important;height:auto!important}
}
</style>`

// injectMobileCompat adds the mobile rescue stylesheet once per page.
func injectMobileCompat(body string) string {
	if strings.Contains(body, `data-hp-mobile-compat`) {
		return body
	}
	return injectAfterHead(body, mobileCompatCSS)
}

// injectAfterHead inserts a block right after the opening <head> tag.
func injectAfterHead(s, block string) string {
	lower := strings.ToLower(s)
	if i := strings.Index(lower, "<head"); i >= 0 {
		if end := strings.IndexByte(s[i:], '>'); end >= 0 {
			j := i + end + 1
			return s[:j] + "\n" + block + s[j:]
		}
	}
	return block + s
}

// injectBeforeBodyEnd appends a block just before </body>.
func injectBeforeBodyEnd(s, block string) string {
	lower := strings.ToLower(s)
	if i := strings.LastIndex(lower, "</body>"); i >= 0 {
		return s[:i] + block + "\n" + s[i:]
	}
	return s + "\n" + block
}

// injectAfterBodyStart inserts a block right after the opening <body> tag.
func injectAfterBodyStart(s, block string) string {
	lower := strings.ToLower(s)
	if i := strings.Index(lower, "<body"); i >= 0 {
		if end := strings.IndexByte(s[i:], '>'); end >= 0 {
			j := i + end + 1
			return s[:j] + "\n" + block + s[j:]
		}
	}
	return block + s
}

func (s *Server) redirect(w http.ResponseWriter, r *http.Request, target string) {
	if !isAbsoluteHTTP(target) {
		s.serveHTML(w, thanksPage)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// parseSubmission extracts all submitted fields plus a best-effort username and
// password. It accepts form-urlencoded, multipart, and JSON bodies.
func (s *Server) parseSubmission(w http.ResponseWriter, r *http.Request) (fields map[string][]string, username, password string) {
	fields = map[string][]string{}
	if s.Cfg.MaxBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, s.Cfg.MaxBodyBytes)
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))

	if strings.Contains(ct, "application/json") {
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		if err := json.Unmarshal(body, &m); err == nil {
			for k, v := range m {
				fields[k] = []string{stringify(v)}
			}
		}
	} else {
		_ = r.ParseForm()
		// r.Form covers both GET query params and POST body, so forms that
		// submit via method="get" are captured too.
		for k, vs := range r.Form {
			fields[k] = vs
		}
	}

	username = pickField(fields, "username", "email", "login", "account", "userid", "用户名", "账号")
	password = pickField(fields, "password", "passwd", "pass", "pwd", "密码")
	fields = capFields(fields)
	username = truncate(username, maxCapturedValue)
	password = truncate(password, maxCapturedValue)
	return fields, username, password
}

const (
	maxCaptureFields = 256
	maxCapturedValue = 4096
)

// capFields bounds attacker-controlled submission size so a single request
// cannot bloat the database with thousands of oversized fields.
func capFields(fields map[string][]string) map[string][]string {
	out := make(map[string][]string, len(fields))
	n := 0
	for k, vs := range fields {
		if n >= maxCaptureFields {
			break
		}
		capped := make([]string, len(vs))
		for i := range vs {
			capped[i] = truncate(vs[i], maxCapturedValue)
		}
		out[truncate(k, 512)] = capped
		n++
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// crossSite reports whether the browser told us the request originated from a
// different site. Absent headers (curl, email clients) are not treated as
// cross-site.
func crossSite(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return true
	}
	ref := r.Header.Get("Origin")
	if ref == "" {
		ref = r.Header.Get("Referer")
	}
	if ref == "" {
		return false
	}
	u, err := url.Parse(ref)
	if err != nil || u.Host == "" {
		return false
	}
	return !strings.EqualFold(u.Host, r.Host)
}

func pickField(fields map[string][]string, keys ...string) string {
	// Case-insensitive exact match first.
	for _, k := range keys {
		for fk, vs := range fields {
			if strings.EqualFold(fk, k) && len(vs) > 0 && strings.TrimSpace(vs[0]) != "" {
				return vs[0]
			}
		}
	}
	// Substring match (e.g. j_username, loginname, 用户名).
	for _, k := range keys {
		for fk, vs := range fields {
			if strings.Contains(strings.ToLower(fk), k) && len(vs) > 0 && strings.TrimSpace(vs[0]) != "" {
				return vs[0]
			}
		}
	}
	return ""
}

// blankPasswords blanks any password-like field so the value is not retained.
func blankPasswords(fields map[string][]string) {
	for fk := range fields {
		switch strings.ToLower(fk) {
		case "password", "pass", "pwd", "passwd":
			fields[fk] = []string{""}
		}
	}
}

func hasAnyValue(fields map[string][]string) bool {
	for _, vs := range fields {
		for _, v := range vs {
			if strings.TrimSpace(v) != "" {
				return true
			}
		}
	}
	return false
}

func stringify(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

// ---------------------------------------------------------------------------
// Admin dispatch

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	// The login form and logout are reachable without a session.
	if r.URL.Path == adminLoginPath {
		s.handleLogin(w, r)
		return
	}
	if r.URL.Path == adminLogoutPath {
		s.handleLogout(w, r)
		return
	}
	if !s.adminAuthorized(r) {
		if strings.HasPrefix(r.URL.Path, "/__admin/api/") {
			s.writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		http.Redirect(w, r, adminLoginPath, http.StatusSeeOther)
		return
	}
	// Cookie-authenticated state-changing requests must come from our own
	// origin. Key/Bearer clients are exempt because browsers never attach them
	// automatically.
	if s.cookieAuth(r) && isUnsafeMethod(r.Method) && !sameOrigin(r) {
		s.writeJSON(w, http.StatusForbidden, map[string]any{"error": "cross-origin request rejected"})
		return
	}
	s.setAdminSecurityHeaders(w)
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.URL.Path == "/__admin" || r.URL.Path == "/__admin/":
		s.adminIndex(w, r)
	case r.URL.Path == "/__admin/api/overview":
		s.adminOverview(w, r)
	case r.URL.Path == "/__admin/api/logs":
		if r.Method == http.MethodGet {
			s.adminLogs(w, r)
			return
		}
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	case r.URL.Path == "/__admin/api/logs/retention" && r.Method == http.MethodPost:
		s.adminLogRetention(w, r)
	case r.URL.Path == "/__admin/api/logs/clear" && r.Method == http.MethodPost:
		s.adminClearLogs(w, r)
	case r.URL.Path == "/__admin/api/settings":
		if r.Method == http.MethodGet {
			s.adminGetSettings(w, r)
			return
		}
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	case r.URL.Path == "/__admin/api/settings/public-url" && r.Method == http.MethodPost:
		s.adminSavePublicURL(w, r)
	case r.URL.Path == "/__admin/api/settings/password" && r.Method == http.MethodPost:
		s.adminSavePassword(w, r)
	case r.URL.Path == "/__admin/api/settings/background" && r.Method == http.MethodPost:
		s.adminUploadBackground(w, r)
	case r.URL.Path == "/__admin/api/bounces":
		if r.Method == http.MethodGet {
			s.adminBounces(w, r)
			return
		}
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	case r.URL.Path == "/__admin/api/bounces/config" && r.Method == http.MethodPost:
		s.adminSaveBounceConfig(w, r)
	case r.URL.Path == "/__admin/api/bounces/poll" && r.Method == http.MethodPost:
		s.adminPollBounces(w, r)
	case r.URL.Path == "/__admin/api/bounces/secret" && r.Method == http.MethodGet:
		s.adminBounceSecret(w, r)
	case r.URL.Path == "/__admin/api/campaigns" && r.Method == http.MethodPost:
		s.adminCreateCampaign(w, r)
	case r.URL.Path == "/__admin/api/templates/import":
		s.adminImportTemplate(w, r)
	case r.URL.Path == "/__admin/api/templates":
		s.adminTemplates(w, r)
	case r.URL.Path == "/__admin/api/attachments":
		s.adminPayloadAttachments(w, r)
	case r.URL.Path == "/__admin/api/pages/import":
		s.adminImportPage(w, r)
	case r.URL.Path == "/__admin/api/pages":
		s.adminPages(w, r)
	case r.URL.Path == "/__admin/api/versions":
		s.adminVersions(w, r)
	case r.URL.Path == "/__admin/api/versions/restore" && r.Method == http.MethodPost:
		s.adminRestoreVersion(w, r)
	case r.URL.Path == "/__admin/api/clone" && r.Method == http.MethodPost:
		s.adminClone(w, r)
	case r.URL.Path == "/__admin/api/groups":
		s.adminGroups(w, r)
	case r.URL.Path == "/__admin/api/profiles":
		s.adminProfiles(w, r)
	case r.URL.Path == "/__admin/api/models":
		s.adminModels(w, r)
	case r.URL.Path == "/__admin/api/llm":
		s.adminLLMConfig(w, r)
	case r.URL.Path == "/__admin/api/llm/models" && r.Method == http.MethodGet:
		s.adminLLMModels(w, r)
	case r.URL.Path == "/__admin/api/llm/secret" && r.Method == http.MethodGet:
		s.adminLLMSecret(w, r)
	case r.URL.Path == "/__admin/api/chat/stream" && r.Method == http.MethodPost:
		s.adminChatStream(w, r)
	case r.URL.Path == "/__admin/api/chat/sessions":
		s.adminChatSessions(w, r)
	case r.URL.Path == "/__admin/api/chat/upload":
		s.adminChatUpload(w, r)
	case r.URL.Path == "/__admin/api/chat/confirm":
		s.adminChatConfirm(w, r)
	case r.URL.Path == "/__admin/api/chat/action/confirm":
		s.adminChatActionConfirm(w, r)
	case r.URL.Path == "/__admin/api/chat/pending":
		s.adminChatPending(w, r)
	case r.URL.Path == "/__admin/api/agent/jobs":
		s.adminAgentJobs(w, r)
	case r.URL.Path == "/__admin/api/agent/metrics":
		s.adminAgentMetrics(w, r)
	case r.URL.Path == "/__admin/api/agent/metrics/global":
		s.adminAgentGlobalMetrics(w, r)
	case r.URL.Path == "/__admin/api/openapi.yaml" && r.Method == http.MethodGet:
		s.adminOpenAPI(w, r)
	case r.URL.Path == "/__admin/api/search" && r.Method == http.MethodGet:
		s.adminSearch(w, r)
	case r.URL.Path == "/__admin/api/suppressions":
		s.adminSuppressions(w, r)
	case r.URL.Path == "/__admin/api/suppressions/bulk" && r.Method == http.MethodPost:
		s.adminBulkSuppress(w, r)
	case r.URL.Path == "/__admin/api/suppressions/delete" && r.Method == http.MethodPost:
		s.adminDeleteSuppression(w, r)
	case r.URL.Path == "/__admin/api/analyze":
		s.adminAnalyze(w, r)
	case r.URL.Path == "/__admin/api/send-history":
		s.adminSendHistory(w, r)
	case r.URL.Path == "/__admin/api/dns-check":
		s.adminDNSCheck(w, r)
	case r.URL.Path == "/__admin/api/report":
		s.adminReport(w, r)
	case r.URL.Path == "/__admin/api/submissions/export":
		s.adminSubmissionsExport(w, r)
	case r.URL.Path == "/__admin/api/jobs":
		s.adminJobs(w, r)
	case r.URL.Path == "/__admin/api/maintenance/purge" && r.Method == http.MethodPost:
		s.adminPurge(w, r)
	default:
		s.adminRoute(w, r)
	}
}

// adminRoute dispatches the id-suffixed routes.
func (s *Server) adminRoute(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/__admin/api/")
	parts := strings.Split(p, "/")
	switch {
	case len(parts) == 2 && parts[0] == "campaigns" && parts[1] == "deleted":
		s.adminDeletedCampaigns(w, r)
		return
	case len(parts) == 2 && parts[0] == "campaigns":
		if id := parseInt(parts[1]); id > 0 {
			if r.Method == http.MethodDelete {
				s.adminDeleteCampaign(w, r, id)
				return
			}
			s.adminCampaign(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "campaigns" && parts[2] == "rename":
		if id := parseInt(parts[1]); id > 0 {
			s.adminRenameCampaign(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "campaigns" && parts[2] == "targets":
		if id := parseInt(parts[1]); id > 0 {
			s.adminAddCampaignTargets(w, r, id)
			return
		}
	case len(parts) == 4 && parts[0] == "campaigns" && parts[2] == "submissions" && parts[3] == "bulk-delete":
		if id := parseInt(parts[1]); id > 0 {
			s.adminBulkDeleteSubmissions(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "campaigns" && parts[2] == "restore":
		if id := parseInt(parts[1]); id > 0 {
			s.adminRestoreCampaign(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "campaigns" && parts[2] == "purge":
		if id := parseInt(parts[1]); id > 0 {
			s.adminPurgeCampaign(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "campaigns" && parts[2] == "schedule":
		if id := parseInt(parts[1]); id > 0 {
			s.adminScheduleSend(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "campaigns" && parts[2] == "submissions":
		if id := parseInt(parts[1]); id > 0 {
			s.adminSubmissions(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "campaigns" && parts[2] == "export":
		if id := parseInt(parts[1]); id > 0 {
			s.adminExport(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "campaigns" && parts[2] == "send":
		if id := parseInt(parts[1]); id > 0 {
			s.adminSend(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "campaigns" && parts[2] == "terminate":
		if id := parseInt(parts[1]); id > 0 {
			s.adminTerminate(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "campaigns" && parts[2] == "profile":
		if id := parseInt(parts[1]); id > 0 && r.Method == http.MethodPost {
			s.adminCampaignProfile(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "campaigns" && parts[2] == "landing-page":
		if id := parseInt(parts[1]); id > 0 && r.Method == http.MethodPost {
			s.adminCampaignLandingPage(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "campaigns" && parts[2] == "resend":
		if id := parseInt(parts[1]); id > 0 && r.Method == http.MethodPost {
			s.adminResend(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "campaigns" && parts[2] == "events":
		if id := parseInt(parts[1]); id > 0 {
			s.adminEvents(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "campaigns" && parts[2] == "failures":
		if id := parseInt(parts[1]); id > 0 {
			s.adminSendFailures(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "campaigns" && parts[2] == "bounces":
		if id := parseInt(parts[1]); id > 0 {
			s.adminCampaignBounces(w, r, id)
			return
		}
	case len(parts) == 4 && parts[0] == "campaigns" && parts[2] == "results":
		if cid, rid := parseInt(parts[1]), parseInt(parts[3]); cid > 0 && rid > 0 && r.Method == http.MethodDelete {
			s.adminDeleteCampaignResult(w, r, cid, rid)
			return
		}
	case len(parts) == 2 && parts[0] == "groups":
		if id := parseInt(parts[1]); id > 0 && r.Method == http.MethodDelete {
			s.adminDeleteGroup(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "groups" && parts[2] == "rename":
		if id := parseInt(parts[1]); id > 0 {
			s.adminRenameGroup(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "groups" && parts[2] == "audit":
		if id := parseInt(parts[1]); id > 0 {
			s.adminGroupAudit(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "groups" && parts[2] == "targets":
		if id := parseInt(parts[1]); id > 0 {
			s.adminGroupTargets(w, r, id)
			return
		}
	case len(parts) == 4 && parts[0] == "groups" && parts[2] == "targets":
		if gid, tid := parseInt(parts[1]), parseInt(parts[3]); gid > 0 && tid > 0 && r.Method == http.MethodDelete {
			s.adminDeleteGroupTarget(w, r, gid, tid)
			return
		}
	case len(parts) == 2 && parts[0] == "profiles":
		if id := parseInt(parts[1]); id > 0 && r.Method == http.MethodDelete {
			s.adminDeleteProfile(w, r, id)
			return
		}
	case len(parts) == 2 && parts[0] == "attachments":
		if id := parseInt(parts[1]); id > 0 && r.Method == http.MethodDelete {
			s.adminPayloadAttachmentDelete(w, r, id)
			return
		}
	case len(parts) == 4 && parts[0] == "agent" && parts[1] == "jobs":
		if id := parseInt(parts[2]); id > 0 {
			s.adminAgentJobAction(w, r, id, parts[3])
			return
		}
	case len(parts) == 3 && parts[0] == "attachments" && parts[2] == "attach":
		if id := parseInt(parts[1]); id > 0 {
			s.adminPayloadAttachmentAttach(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "profiles" && parts[2] == "secret":
		if id := parseInt(parts[1]); id > 0 {
			s.adminProfileSecret(w, r, id)
			return
		}
	case len(parts) == 2 && parts[0] == "pages":
		if id := parseInt(parts[1]); id > 0 && r.Method == http.MethodDelete {
			s.adminDeletePage(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "pages" && parts[2] == "preview.png":
		if id := parseInt(parts[1]); id > 0 {
			s.adminPagePreview(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "pages" && parts[2] == "rename":
		if id := parseInt(parts[1]); id > 0 {
			s.adminRenamePage(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "pages" && parts[2] == "e2e":
		if id := parseInt(parts[1]); id > 0 {
			s.adminPageE2E(w, r, id)
			return
		}
	case len(parts) == 2 && parts[0] == "versions":
		if id := parseInt(parts[1]); id > 0 {
			s.adminContentVersion(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "jobs" && parts[2] == "cancel":
		if id := parseInt(parts[1]); id > 0 {
			s.adminCancelJob(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "chat" && parts[1] == "sessions":
		if id := parseInt(parts[2]); id > 0 {
			s.adminChatSession(w, r, id)
			return
		}
	case len(parts) == 2 && parts[0] == "templates":
		if id := parseInt(parts[1]); id > 0 && r.Method == http.MethodDelete {
			s.adminDeleteTemplate(w, r, id)
			return
		}
	case len(parts) == 3 && parts[0] == "templates" && parts[2] == "rename":
		if id := parseInt(parts[1]); id > 0 {
			s.adminRenameTemplate(w, r, id)
			return
		}
	}
	s.notFound(w)
}

// ---------------------------------------------------------------------------
// Helpers

func (s *Server) adminIndex(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("static/admin.html")
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": "console missing"})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	_, _ = w.Write(data)
}

// serveStatic serves an embedded vendor/static asset.
func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request, path string) {
	data, err := staticFS.ReadFile(path)
	if err != nil {
		s.notFound(w)
		return
	}
	ct := "application/octet-stream"
	switch {
	case strings.HasSuffix(path, ".js"):
		ct = "application/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		ct = "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".png"):
		ct = "image/png"
	case strings.HasSuffix(path, ".jpg"), strings.HasSuffix(path, ".jpeg"):
		ct = "image/jpeg"
	case strings.HasSuffix(path, ".svg"):
		ct = "image/svg+xml"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(200)
	_, _ = w.Write(data)
}

func (s *Server) adminAuthorized(r *http.Request) bool {
	if s.sessionFromRequest(r, adminCookieName) {
		return true
	}
	key := s.Cfg.AdminKey
	if key == "" {
		return false
	}
	// Only accept the key in an Authorization header. A query-string key ends
	// up in browser history, proxy logs and Referer headers.
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(key)) == 1
}

func isUnsafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// RunRetention purges captured submissions and tracking events older than the
// configured retention window, once at startup and then daily. It is intended
// to run as a goroutine for the process lifetime.
func (s *Server) RunRetention() {
	s.purgeOldData()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		s.purgeOldData()
	}
}

func (s *Server) purgeOldData() {
	days := s.Cfg.RetentionDays
	if days <= 0 || s.Store == nil {
		return
	}
	s.pruneLogs(s.appSettingsSnapshot().LogRetentionDays)
	cutoff := time.Now().AddDate(0, 0, -days)
	subs, events, err := s.Store.PurgeOlderThan(cutoff)
	if err != nil {
		s.log().Error("retention purge", "err", err)
		return
	}
	if subs > 0 || events > 0 {
		s.log().Info("retention purge", "days", days, "submissions", subs, "events", events)
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) notFound(w http.ResponseWriter) {
	s.writeJSON(w, 404, map[string]any{"error": "not found"})
}

// remoteIP returns the client IP. X-Forwarded-For is only honoured when the
// direct peer is a configured trusted proxy; otherwise any client could spoof
// the address recorded in captured evidence.
func (s *Server) remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil || !s.isTrustedProxy(ip) {
		return host
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}
	// Walk right-to-left and take the first address that is not another
	// trusted proxy. Proxies append the real peer, so client-supplied entries
	// on the left cannot win.
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		cand := net.ParseIP(strings.TrimSpace(parts[i]))
		if cand == nil {
			continue
		}
		if !s.isTrustedProxy(cand) {
			return cand.String()
		}
	}
	return host
}

func (s *Server) isTrustedProxy(ip net.IP) bool {
	s.trustOnce.Do(func() {
		for _, raw := range s.Cfg.TrustedProxies {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			if _, n, err := net.ParseCIDR(raw); err == nil {
				s.trustedNets = append(s.trustedNets, n)
				continue
			}
			if single := net.ParseIP(raw); single != nil {
				bits := 128
				if single.To4() != nil {
					bits = 32
				}
				s.trustedNets = append(s.trustedNets, &net.IPNet{IP: single, Mask: net.CIDRMask(bits, bits)})
			}
		}
	})
	for _, n := range s.trustedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) writeGIF(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	_, _ = w.Write(pixelGIF)
}

func isAbsoluteHTTP(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func parseInt(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

var pixelGIF = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
	0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
	0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
}

const reportedPage = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>举报已收到</title></head><body style="font-family:system-ui,sans-serif;text-align:center;padding:60px">
<h2>✅ 举报已收到</h2><p>感谢您的安全意识。该邮件已被记录为「已举报」。</p>
</body></html>`

const terminatedPage = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>系统维护中</title></head><body style="font-family:system-ui,sans-serif;text-align:center;padding:60px;color:#666">
<h2>系统维护中</h2><p>该页面正在维护，请稍后再试。</p>
</body></html>`

const benignPage = `<!doctype html><html><head><meta charset="utf-8"><title>403 Forbidden</title>
</head><body><h1>403 Forbidden</h1></body></html>`

const thanksPage = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>操作成功</title></head><body style="font-family:system-ui,sans-serif;text-align:center;padding:60px;color:#555">
<h2>操作成功</h2><p>您已成功完成操作。</p>
</body></html>`

const unsubscribedPage = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>已退订</title></head><body style="font-family:system-ui,sans-serif;text-align:center;padding:60px;color:#555">
<h2>已退订</h2><p>您已成功退订，将不再收到此类演练邮件。</p>
</body></html>`

// beaconJS is injected into every landing page to record behavior events.
const beaconJS = `(function(){
var rid="__RID__", base="__BASE__";
function send(k,d){try{var i=new Image();i.src=base+"/b/"+rid+"/"+k+(d?"?d="+encodeURIComponent(d):"");}catch(e){}}
var t0=Date.now();
send("page_load", location.pathname);
var dwell=0;
var hb=setInterval(function(){dwell+=5;send("dwell",String(dwell));},5000);
window.addEventListener("beforeunload",function(){try{clearInterval(hb);}catch(e){}send("dwell",String(Math.round((Date.now()-t0)/1000)));});
document.addEventListener("click",function(e){var t=e.target;if(!t)return;var tag=t.tagName||"";send("page_click",tag+(t.id?"#"+t.id:"")+(t.name?"["+t.name+"]":""));},true);
document.addEventListener("focusin",function(e){var t=e.target;if(t&&t.tagName==="INPUT"){send("field_focus",(t.name||t.id||t.type||"input"));}},true);
document.addEventListener("submit",function(){send("submit_attempt","");},true);
})();`
