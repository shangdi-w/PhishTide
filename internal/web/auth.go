package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"html"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	adminCookieName   = "phish_admin"   // Path=/__admin
	adminPreviewName  = "phish_admin_p" // Path=/p/
	adminLoginPath    = "/__admin/login"
	adminLogoutPath   = "/__admin/logout"
	loginMaxFails     = 5
	loginFailWindow   = 15 * time.Minute
	loginLockDuration = 15 * time.Minute
)

// loginLimiter is a small in-memory per-IP failure counter. It is deliberately
// not persisted: a restart resets lockouts, which is acceptable for a console.
type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempt
}

type loginAttempt struct {
	fails       int
	windowStart time.Time
	lockedUntil time.Time
}

func (l *loginLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.attempts == nil {
		l.attempts = map[string]*loginAttempt{}
	}
	a := l.attempts[key]
	if a == nil {
		return true
	}
	now := time.Now()
	if now.Before(a.lockedUntil) {
		return false
	}
	if now.Sub(a.windowStart) > loginFailWindow {
		delete(l.attempts, key)
		return true
	}
	return true
}

func (l *loginLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.attempts == nil {
		l.attempts = map[string]*loginAttempt{}
	}
	now := time.Now()
	a := l.attempts[key]
	if a == nil || now.Sub(a.windowStart) > loginFailWindow {
		a = &loginAttempt{windowStart: now}
		l.attempts[key] = a
	}
	a.fails++
	if a.fails >= loginMaxFails {
		a.lockedUntil = now.Add(loginLockDuration)
	}
	// Bound memory use: drop stale entries once the map grows.
	if len(l.attempts) > 4096 {
		for k, v := range l.attempts {
			if now.Sub(v.windowStart) > time.Hour && now.After(v.lockedUntil) {
				delete(l.attempts, k)
			}
		}
	}
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}

// loginEnabled reports whether a console password is configured at all.
func (s *Server) loginEnabled() bool {
	return s.Cfg.AdminPass != "" || s.Cfg.AdminPassHash != "" || s.Cfg.AdminKey != "" ||
		s.appSettingsSnapshot().AdminHash != ""
}

// checkCredentials verifies a console username/password pair. Comparisons are
// constant-time; AdminPassHash (bcrypt) takes precedence when present. When no
// password is configured the legacy admin key doubles as the password.
func (s *Server) checkCredentials(user, pass string) bool {
	if !s.loginEnabled() || strings.Contains(s.Cfg.AdminUser, "|") {
		return false
	}
	wantUser := sha256.Sum256([]byte(s.Cfg.AdminUser))
	gotUser := sha256.Sum256([]byte(user))
	userOK := subtle.ConstantTimeCompare(wantUser[:], gotUser[:]) == 1

	// A password changed from the console is stored as a bcrypt hash and wins
	// over the launch flags.
	if h := s.appSettingsSnapshot().AdminHash; h != "" {
		err := bcrypt.CompareHashAndPassword([]byte(h), []byte(pass))
		return userOK && err == nil
	}

	if s.Cfg.AdminPassHash != "" {
		// Always run bcrypt so a wrong username does not answer measurably
		// faster than a wrong password.
		err := bcrypt.CompareHashAndPassword([]byte(s.Cfg.AdminPassHash), []byte(pass))
		return userOK && err == nil
	}
	expected := s.Cfg.AdminPass
	if expected == "" {
		expected = s.Cfg.AdminKey
	}
	if expected == "" {
		return false
	}
	wantPass := sha256.Sum256([]byte(expected))
	gotPass := sha256.Sum256([]byte(pass))
	return userOK && subtle.ConstantTimeCompare(wantPass[:], gotPass[:]) == 1
}

// sessionKeyBytes returns the HMAC key used to sign console cookies. The
// credential fingerprint is mixed in so changing the password invalidates every
// existing session.
func (s *Server) sessionKeyBytes() []byte {
	base := s.SessionKey
	if len(base) == 0 {
		sum := sha256.Sum256([]byte("phishsim-session"))
		base = sum[:]
	}
	cred := s.appSettingsSnapshot().AdminHash
	if cred == "" {
		cred = s.Cfg.AdminPassHash
	}
	if cred == "" {
		cred = s.Cfg.AdminPass
	}
	if cred == "" {
		cred = s.Cfg.AdminKey
	}
	mac := hmac.New(sha256.New, base)
	mac.Write([]byte("session|" + s.Cfg.AdminUser + "|" + cred))
	return mac.Sum(nil)
}

func (s *Server) newSessionToken() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	exp := time.Now().Add(s.Cfg.SessionTTL).Unix()
	payload := s.Cfg.AdminUser + "|" + strconv.FormatInt(exp, 10) + "|" + base64.RawURLEncoding.EncodeToString(nonce)
	enc := base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, s.sessionKeyBytes())
	mac.Write([]byte(enc))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return enc + "." + sig, nil
}

func (s *Server) validSessionToken(token string) bool {
	enc, sig, ok := strings.Cut(token, ".")
	if !ok || enc == "" || sig == "" {
		return false
	}
	wantSig, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, s.sessionKeyBytes())
	mac.Write([]byte(enc))
	if !hmac.Equal(wantSig, mac.Sum(nil)) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(raw), "|", 3)
	if len(parts) != 3 {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(parts[0]), []byte(s.Cfg.AdminUser)) != 1 {
		return false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	return true
}

func (s *Server) sessionFromRequest(r *http.Request, name string) bool {
	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return false
	}
	return s.validSessionToken(c.Value)
}

// cookieAuth reports whether the request was authenticated by a session cookie
// (as opposed to an explicit API key). CSRF checks only apply to cookie auth.
func (s *Server) cookieAuth(r *http.Request) bool {
	return s.sessionFromRequest(r, adminCookieName) || s.sessionFromRequest(r, adminPreviewName)
}

func (s *Server) setSessionCookies(w http.ResponseWriter) error {
	token, err := s.newSessionToken()
	if err != nil {
		return err
	}
	maxAge := int(s.Cfg.SessionTTL.Seconds())
	common := func(name, path string) *http.Cookie {
		return &http.Cookie{
			Name:     name,
			Value:    token,
			Path:     path,
			MaxAge:   maxAge,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		}
	}
	http.SetCookie(w, common(adminCookieName, "/__admin"))
	http.SetCookie(w, common(adminPreviewName, "/p/"))
	return nil
}

func (s *Server) clearSessionCookies(w http.ResponseWriter) {
	for _, c := range []*http.Cookie{
		{Name: adminCookieName, Path: "/__admin", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode},
		{Name: adminPreviewName, Path: "/p/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode},
	} {
		http.SetCookie(w, c)
	}
}

// sameOrigin rejects cross-site browser requests. Requests without Origin and
// Referer (curl, server-to-server API clients) are allowed; those clients must
// authenticate with the API key rather than a cookie.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.loginEnabled() {
		s.notFound(w)
		return
	}
	s.setAdminSecurityHeaders(w)
	if s.adminAuthorized(r) && r.Method == http.MethodGet {
		http.Redirect(w, r, "/__admin", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		s.writeLoginPage(w, http.StatusOK, "")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		s.writeLoginPage(w, http.StatusMethodNotAllowed, "请求方式不支持")
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(r) {
		s.writeLoginPage(w, http.StatusForbidden, "来源校验失败")
		return
	}
	ip := s.remoteIP(r)
	if !s.loginLimiter.allow(ip) {
		s.writeLoginPage(w, http.StatusTooManyRequests, "尝试次数过多，请 15 分钟后再试")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		s.writeLoginPage(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if !s.checkCredentials(r.PostFormValue("username"), r.PostFormValue("password")) {
		s.loginLimiter.fail(ip)
		s.log().Warn("admin login failed", "ip", ip)
		s.writeLoginPage(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	s.loginLimiter.reset(ip)
	if err := s.setSessionCookies(w); err != nil {
		s.log().Error("create admin session", "err", err)
		s.writeLoginPage(w, http.StatusInternalServerError, "会话创建失败，请重试")
		return
	}
	s.log().Info("admin login", "ip", ip)
	http.Redirect(w, r, "/__admin", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST only"})
		return
	}
	if s.cookieAuth(r) && !sameOrigin(r) {
		s.writeJSON(w, http.StatusForbidden, map[string]any{"error": "cross-origin request rejected"})
		return
	}
	s.clearSessionCookies(w)
	if r.Header.Get("Accept") != "" && strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, adminLoginPath, http.StatusSeeOther)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"logged_out": true})
}

func (s *Server) writeLoginPage(w http.ResponseWriter, status int, errMsg string) {
	st := s.appSettingsSnapshot()
	page := strings.Replace(loginPageHTML, "{{SERVER}}", html.EscapeString(s.Cfg.AdminUser), 1)
	page = strings.Replace(page, "{{BRAND}}", html.EscapeString(displayBrandName), -1)
	page = strings.Replace(page, "{{TAGLINE}}", html.EscapeString(displayBrandTagline), -1)
	page = strings.Replace(page, "{{BG}}", html.EscapeString(backgroundURL(st.BackgroundVersion)), 1)
	if st.BackgroundVersion != "" {
		page = strings.Replace(page, "{{BODYCLASS}}", "has-bg", 1)
	} else {
		page = strings.Replace(page, "{{BODYCLASS}}", "", 1)
	}
	page = strings.Replace(page, "{{ERROR}}", loginErrorHTML(errMsg), 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(page))
}

func (s *Server) setAdminSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; connect-src 'self'; font-src 'self' data:; object-src 'none'; "+
			"base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
}

const loginPageHTML = `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>登录 · {{BRAND}}</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:#f5f7fa;
  font-family:system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
.card{width:360px;max-width:92vw;background:#fff;
  border-radius:12px;padding:32px 28px;box-shadow:0 20px 50px rgba(15,23,42,.12)}
.logo{font-size:20px;font-weight:700;text-align:center;margin-bottom:6px}
.sub{text-align:center;color:#94a3b8;font-size:12px;margin-bottom:24px}
label{display:block;font-size:13px;color:#334155;margin:14px 0 6px}
body.has-bg{background:#0f172a url('{{BG}}') right center/cover no-repeat fixed}
body.has-bg .card{background:rgba(255,255,255,.6);border:1px solid rgba(255,255,255,.5);
  -webkit-backdrop-filter:blur(18px) saturate(130%);backdrop-filter:blur(18px) saturate(130%);
  box-shadow:0 20px 50px rgba(0,0,0,.35)}
body.has-bg .sub{color:#475569}
body.has-bg label{color:#1f2937}
input{width:100%;padding:10px 12px;border:1px solid #cbd5e1;border-radius:8px;font-size:16px;outline:none}
input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.15)}
button{width:100%;margin-top:22px;padding:11px;border:0;border-radius:8px;background:#3b82f6;color:#fff;
  font-size:15px;font-weight:600;cursor:pointer}
button:hover{background:#2563eb}
.err{margin-top:14px;padding:9px 12px;border-radius:8px;background:#fef2f2;color:#b91c1c;font-size:13px}
.foot{margin-top:18px;text-align:center;color:#94a3b8;font-size:11px}
.author{position:fixed;left:0;right:0;bottom:calc(16px + env(safe-area-inset-bottom));text-align:center;color:#64748b;font-size:12px;letter-spacing:1px}
.author .ver{display:inline;margin-left:8px;font-size:11px;color:#94a3b8;letter-spacing:1.5px}
body.has-bg .foot{color:#64748b}
body.has-bg .author{color:#cbd5e1;text-shadow:0 1px 6px rgba(0,0,0,.65)}
</style>
</head>
<body class="{{BODYCLASS}}">
<form class="card" method="post" action="/__admin/login" autocomplete="off">
  <div class="logo">🎣 {{BRAND}}</div>
  <div class="sub">{{TAGLINE}} · 请先登录</div>
  <label for="u">用户名</label>
  <input id="u" name="username" autocomplete="username" required autofocus>
  <label for="p">密码</label>
  <input id="p" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">登 录</button>
  {{ERROR}}
  <div class="foot">{{BRAND}} · 账号 {{SERVER}} · 仅限授权运营人员</div>
</form>
<div class="author">作者<span class="ver">v1.0</span></div>
</body>
</html>`

// loginErrorHTML renders the inline error block. Messages are fixed strings
// from handleLogin, never user-controlled input.
func loginErrorHTML(msg string) string {
	if msg == "" {
		return ""
	}
	return `<div class="err">` + msg + `</div>`
}
