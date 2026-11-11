package clone

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// netResource is one same-origin response observed while the browser rendered
// a page. API marks XHR/fetch JSON, which the SPA shim replays locally.
type netResource struct {
	URL  string
	Mime string
	Body []byte
	API  bool
}

// CloneRendered navigates to url in a headless browser, waits for the page to
// render (SPA/dynamic content), and returns the full rendered HTML and final
// URL. It handles sites that a plain GET can't: JavaScript shells, client-side
// redirects, and JSON-encoded redirect instructions.
func CloneRendered(url string, timeout time.Duration) (html, finalURL string, err error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := chromedp.Do(ctx,
		chromedp.Navigate(url),
		chromedp.WaitReady(chromedp.CSS("body")),
	); err != nil {
		return "", "", err
	}
	// Prefer waiting for the credential form over a fixed sleep: SSO pages
	// finish their layout when the login widget mounts. A timeout is not fatal,
	// the page may legitimately have no password field (OAuth consent, etc.).
	waitCtx, waitCancel := context.WithTimeout(ctx, 8*time.Second)
	_ = chromedp.Do(waitCtx, chromedp.WaitVisible(chromedp.CSS(`input[type="password"]`)))
	waitCancel()
	time.Sleep(800 * time.Millisecond) // let async assets settle

	if html, err = chromedp.Run(ctx, chromedp.OuterHTML(chromedp.CSS("html"))); err != nil {
		return "", "", err
	}
	if finalURL, err = chromedp.Run(ctx, chromedp.Location()); err != nil {
		return "", "", err
	}
	return html, finalURL, nil
}

// CloneWithBrowser fetches and renders url with a headless browser, then
// mirrors and rewrites the rendered HTML exactly like Clone. It is the
// preferred path for SPA and dynamic sites; callers should fall back to Clone
// when a browser is unavailable.
func CloneWithBrowser(opts Options) (*Result, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("clone: url required")
	}
	opts.applyDefaults()

	var rendered, finalURL string
	var captured []netResource
	var err error
	if opts.CaptureNet {
		rendered, finalURL, captured, err = CloneRenderedNetwork(opts.URL, opts.Timeout, opts.MaxAssetSize)
	} else {
		rendered, finalURL, err = CloneRendered(opts.URL, opts.Timeout)
	}
	if err != nil {
		return nil, fmt.Errorf("clone render: %w", err)
	}
	final, err := url.Parse(finalURL)
	if err != nil || final == nil || final.Host == "" {
		final, _ = url.Parse(opts.URL)
	}
	body := []byte(rendered)

	res := &Result{
		ContentType: "text/html; charset=utf-8",
		FinalURL:    finalURL,
		Assets:      map[string]Asset{},
	}
	res.SPA = isSPA(body)

	// Seed the mirror with everything the browser fetched, so lazy chunks and
	// API payloads that never appear in the HTML are captured too. Capture is
	// already priority-ordered (API, scripts, styles, rest); the budget keeps a
	// chatty SPA from writing hundreds of assets into the database.
	seed := map[string]Asset{}
	for _, r := range captured {
		if len(seed) >= opts.MaxAssets {
			break
		}
		seed[r.URL] = Asset{URL: r.URL, ContentType: r.Mime, Body: r.Body}
	}

	client := newClient(opts)
	if opts.MirrorAssets {
		res.Assets = mirrorAssets(client, final, body, opts, seed)
	}

	assetMap := assetPathMap(res.Assets)
	apiMap := apiReplayMap(captured, res.Assets)

	res.CapturedAPI = len(apiMap)
	out := rewriteHTML(body, final, opts, res.Assets)
	if opts.StaticForm {
		out = staticFormTransform(out)
	} else if res.SPA && opts.SPAShim {
		out = injectSPAShim(out, assetMap, apiMap)
	}
	res.Body = out
	fillDiagnostics(res)
	return res, nil
}

// CloneRenderedNetwork is CloneRendered plus a DevTools network recorder. It
// returns the rendered HTML, the final URL, and every same-origin response the
// browser loaded (main document excluded; XHR/fetch JSON is flagged).
func CloneRenderedNetwork(pageURL string, timeout time.Duration, maxAssetSize int64) (html, finalURL string, out []netResource, err error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if maxAssetSize <= 0 {
		maxAssetSize = defaultMaxAsset
	}
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()

	type meta struct {
		url  string
		typ  network.ResourceType
		mime string
	}
	var mu sync.Mutex
	reqs := map[network.RequestID]meta{}
	order := []network.RequestID{}
	seen := map[network.RequestID]bool{}

	// Subscribing starts before navigation, so the first request is recorded.
	reqEvents := chromedp.Events(ctx, network.RequestWillBeSent)
	respEvents := chromedp.Events(ctx, network.ResponseReceived)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for e, err := range reqEvents {
			if err != nil || e.Request == nil || e.Request.URL == "" {
				continue
			}
			mu.Lock()
			if !seen[e.RequestID] {
				seen[e.RequestID] = true
				order = append(order, e.RequestID)
			}
			reqs[e.RequestID] = meta{url: e.Request.URL, typ: e.Type}
			mu.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		for e, err := range respEvents {
			if err != nil || e.Response == nil {
				continue
			}
			mu.Lock()
			m := reqs[e.RequestID]
			if m.url == "" {
				m.url = e.Response.URL
			}
			m.typ = e.Type
			m.mime = e.Response.MimeType
			reqs[e.RequestID] = m
			mu.Unlock()
		}
	}()

	enable := func(ctx context.Context, t *chromedp.Target) (chromedp.Void, error) {
		_, err := cdp.Call(ctx, t, network.Enable, network.EnableParams{})
		return chromedp.Void{}, err
	}
	if err := chromedp.Do(ctx, enable,
		chromedp.Navigate(pageURL),
		chromedp.WaitReady(chromedp.CSS("body")),
	); err != nil {
		return "", "", nil, err
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 8*time.Second)
	_ = chromedp.Do(waitCtx, chromedp.WaitVisible(chromedp.CSS(`input[type="password"]`)))
	waitCancel()
	time.Sleep(1200 * time.Millisecond) // let async chunks and API calls settle

	if html, err = chromedp.Run(ctx, chromedp.OuterHTML(chromedp.CSS("html"))); err != nil {
		return "", "", nil, err
	}
	if finalURL, err = chromedp.Run(ctx, chromedp.Location()); err != nil {
		return "", "", nil, err
	}

	mu.Lock()
	ids := append([]network.RequestID(nil), order...)
	list := make([]meta, len(ids))
	for i, id := range ids {
		list[i] = reqs[id]
	}
	mu.Unlock()

	page, perr := url.Parse(finalURL)
	if perr != nil {
		page, _ = url.Parse(pageURL)
	}

	// Fetch bodies, most valuable first (API, scripts, styles before images).
	idx := make([]int, 0, len(ids))
	for i, m := range list {
		if m.url == "" || m.typ == network.ResourceTypeDocument || m.typ == network.ResourceTypePreflight {
			continue
		}
		if page != nil {
			if u, err := url.Parse(m.url); err != nil || !strings.EqualFold(u.Host, page.Host) {
				continue
			}
		}
		idx = append(idx, i)
	}
	sort.SliceStable(idx, func(a, b int) bool {
		return resourceRank(list[idx[a]].typ) < resourceRank(list[idx[b]].typ)
	})

	seenURL := map[string]bool{}
	for _, i := range idx {
		m := list[i]
		if seenURL[m.url] {
			continue
		}
		seenURL[m.url] = true
		body, ok := fetchResponseBody(ctx, ids[i], maxAssetSize)
		if !ok {
			continue
		}
		mime := m.mime
		if mime == "" {
			mime = mimeFromURL(m.url)
		}
		api := (m.typ == network.ResourceTypeXHR || m.typ == network.ResourceTypeFetch) &&
			(strings.Contains(strings.ToLower(mime), "json") || strings.HasSuffix(mime, "+json"))
		out = append(out, netResource{URL: m.url, Mime: mime, Body: body, API: api})
	}
	return html, finalURL, out, nil
}

// assetPathMap maps each mirrored asset's URL pathname to its published local
// path, so the SPA shim can point runtime-constructed URLs at the mirror.
func assetPathMap(assets map[string]Asset) map[string]string {
	out := make(map[string]string, len(assets))
	for k, a := range assets {
		if u, err := url.Parse(k); err == nil && u.Path != "" {
			out[u.Path] = a.Path
		}
	}
	return out
}

// apiReplayMap turns captured XHR/fetch JSON into path(+query) -> mirrored path,
// which the SPA shim uses to answer the app's own calls locally. Responses that
// were not mirrored (over budget, non-JSON) are left out.
func apiReplayMap(captured []netResource, assets map[string]Asset) map[string]string {
	out := map[string]string{}
	for _, r := range captured {
		if !r.API {
			continue
		}
		a, ok := assets[r.URL]
		if !ok || a.Path == "" {
			continue
		}
		u, err := url.Parse(r.URL)
		if err != nil || u.Path == "" {
			continue
		}
		key := u.Path
		if u.RawQuery != "" {
			key += "?" + u.RawQuery
		}
		out[key] = a.Path
	}
	return out
}

// resourceRank orders captured resources so the most useful bodies are fetched
// before the browser's buffer is reused by later traffic.
func resourceRank(t network.ResourceType) int {
	switch t {
	case network.ResourceTypeXHR, network.ResourceTypeFetch:
		return 0
	case network.ResourceTypeScript:
		return 1
	case network.ResourceTypeStylesheet:
		return 2
	case network.ResourceTypeManifest, network.ResourceTypeOther, network.ResourceTypeMedia:
		return 3
	default:
		return 4
	}
}

// fetchResponseBody retrieves one buffered response body from the browser.
func fetchResponseBody(ctx context.Context, id network.RequestID, max int64) ([]byte, bool) {
	body, err := chromedp.Run(ctx, func(ctx context.Context, t *chromedp.Target) ([]byte, error) {
		res, err := cdp.Call(ctx, t, network.GetResponseBody, network.GetResponseBodyParams{RequestID: id})
		if err != nil {
			return nil, err
		}
		return res.Body, nil
	})
	if err != nil || len(body) == 0 || int64(len(body)) > max {
		return nil, false
	}
	return body, true
}

// mimeFromURL guesses a content type from the path extension.
func mimeFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	switch strings.ToLower(pathExt(u.Path)) {
	case ".js", ".mjs":
		return "application/javascript"
	case ".css":
		return "text/css"
	case ".json":
		return "application/json"
	case ".wasm":
		return "application/wasm"
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".woff2":
		return "font/woff2"
	case ".woff":
		return "font/woff"
	}
	return ""
}

// pathExt returns a path's extension including the leading dot.
func pathExt(p string) string {
	i := strings.LastIndexByte(p, '.')
	if i < 0 {
		return ""
	}
	return p[i:]
}

// SubmitResult reports what a headless browser did with a page's form.
type SubmitResult struct {
	Filled    []string `json:"filled"`
	StartURL  string   `json:"start_url"`
	FinalURL  string   `json:"final_url"`
	Submitted bool     `json:"submitted"`
}

// submitFormJS fills every visible text-like input with a recognizable test
// value and submits the first form. It uses the native value setter so
// React/Vue controlled inputs also see the change.
const submitFormJS = `(() => {
  const skip = new Set(['hidden','checkbox','radio','submit','button','file','image','reset']);
  const inputs = Array.from(document.querySelectorAll('input, textarea'))
    .filter(el => !skip.has((el.type || 'text').toLowerCase()));
  if (!inputs.length) return null;
  const filled = [];
  for (const el of inputs) {
    const type = (el.type || 'text').toLowerCase();
    const name = (el.name || el.id || '').toLowerCase();
    let value = 'e2e-user';
    if (type === 'password') value = 'E2E-Pass-123!';
    else if (type === 'email' || name.includes('mail')) value = 'e2e@example.invalid';
    else if (type === 'tel') value = '13800000000';
    try { el.focus(); } catch (_) {}
    const proto = el.tagName === 'TEXTAREA' ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
    setter.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    filled.push(el.name || el.id || type);
  }
  window.__hpE2E = filled;
  const btn = document.querySelector('button[type=submit], input[type=submit], button');
  if (btn) btn.click();
  else { const f = document.querySelector('form'); if (f) f.submit(); }
  return filled;
})()`

// SubmitForm fills and submits the first form on a page, returning the fields
// it touched, the landing URL and the final URL. It uses a normal desktop
// Chrome user agent so the platform's own bot filter does not drop the
// submission, which is what makes this an end-to-end check rather than a
// scripted POST.
func SubmitForm(pageURL string, timeout time.Duration) (SubmitResult, error) {
	out := SubmitResult{StartURL: pageURL}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), chromedp.UserAgent(ua))
	defer allocCancel()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := chromedp.Do(ctx,
		chromedp.EmulateViewport(1280, 900),
		chromedp.Navigate(pageURL),
		chromedp.WaitReady(chromedp.CSS("body")),
		chromedp.Sleep(300*time.Millisecond),
	); err != nil {
		return out, fmt.Errorf("submit form: %w", err)
	}
	filled, err := chromedp.Run(ctx, chromedp.Evaluate[[]string](submitFormJS))
	if err != nil {
		return out, fmt.Errorf("submit form: %w", err)
	}
	if filled == nil {
		return out, fmt.Errorf("页面没有可填写的输入框或表单")
	}
	out.Filled = filled

	// Wait for navigation. A form that only shows an inline error stays on the
	// same URL and is reported as not submitted.
	deadline := time.Now().Add(8 * time.Second)
	for {
		loc, err := chromedp.Run(ctx, chromedp.Location())
		if err != nil {
			break
		}
		out.FinalURL = loc
		if loc != pageURL && loc != strings.TrimSuffix(pageURL, "/") && loc != strings.TrimSuffix(pageURL, "/")+"/" {
			out.Submitted = true
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return out, nil
}

// ScreenshotURL loads url in a headless browser and returns a full-page PNG.
// It is used to preview a landing page before a campaign is launched; assets
// resolve relative to url exactly as they will for a recipient.
func ScreenshotURL(url string, timeout time.Duration) ([]byte, error) {
	return Screenshot(url, timeout, 100)
}

// ScreenshotJPEG renders a full-page JPEG at the given quality (1-99). JPEG is
// small enough to hand to a multimodal model.
func ScreenshotJPEG(url string, timeout time.Duration, quality int) ([]byte, error) {
	if quality <= 0 || quality >= 100 {
		quality = 70
	}
	return Screenshot(url, timeout, quality)
}

// Screenshot loads url in a headless browser. quality 100 yields PNG, any
// other value yields JPEG at that quality.
func Screenshot(url string, timeout time.Duration, quality int) ([]byte, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := chromedp.Do(ctx,
		chromedp.EmulateViewport(1280, 900),
		chromedp.Navigate(url),
		chromedp.WaitReady(chromedp.CSS("body")),
		chromedp.Sleep(700*time.Millisecond),
	); err != nil {
		return nil, fmt.Errorf("screenshot: %w", err)
	}
	shot, err := chromedp.Run(ctx, chromedp.FullScreenshot(quality))
	if err != nil {
		return nil, fmt.Errorf("screenshot: %w", err)
	}
	return shot, nil
}
