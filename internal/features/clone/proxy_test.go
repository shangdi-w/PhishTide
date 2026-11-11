package clone

import (
	"net/url"
	"strings"
	"testing"
)

const proxyTestPrefix = "/l/ab12/px/"

func TestProxyURL(t *testing.T) {
	base, _ := url.Parse("https://sso.example.com/login?next=%2Fapp")
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"/api/login", "/l/ab12/px/api/login", true},
		{"/", "/l/ab12/px/", true},
		{"https://sso.example.com/static/app.js", "/l/ab12/px/static/app.js", true},
		{"//sso.example.com/x.png", "/l/ab12/px/x.png", true},
		{"https://cdn.example.com/lib.js", "", false},
		{"data:image/png;base64,AAAA", "", false},
		{"javascript:void(0)", "", false},
		{"#anchor", "", false},
		{"relative/path.js", "", false},
	}
	for _, c := range cases {
		got, ok := ProxyURL(c.in, base, proxyTestPrefix)
		if got != c.want || ok != c.ok {
			t.Errorf("ProxyURL(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestProxyRewriteHTML(t *testing.T) {
	base, _ := url.Parse("https://sso.example.com/login")
	doc := []byte(`<!doctype html><html><head>
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
<base href="/">
<link rel="stylesheet" href="/style.css" integrity="sha384-x">
<link rel="stylesheet" href="https://cdn.example.com/other.css">
<script src="/static/app.js"></script>
</head><body style="background:url(/bg.png)">
<a href="/home">home</a>
<img src="/img/logo.png" srcset="/img/logo@2x.png 2x">
<form method="post" action="/login"><input name="password" type="password"></form>
</body></html>`)
	out := string(ProxyRewriteHTML(doc, base, proxyTestPrefix))

	for _, want := range []string{
		`href="/l/ab12/px/style.css"`,
		`src="/l/ab12/px/static/app.js"`,
		`href="/l/ab12/px/home"`,
		`src="/l/ab12/px/img/logo.png"`,
		`/l/ab12/px/img/logo@2x.png`,
		`action="/l/ab12/px/login"`,
		`url(&quot;/l/ab12/px/bg.png&quot;)`,
		`<base href="/l/ab12/px/">`,
		`data-hp-proxy="1"`,
		`__HP_PROXY__`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rewritten HTML missing %q\n%s", want, out)
		}
	}
	for _, bad := range []string{"Content-Security-Policy", "integrity="} {
		if strings.Contains(out, bad) {
			t.Errorf("rewritten HTML should not contain %q\n%s", bad, out)
		}
	}
	if !strings.Contains(out, `href="https://cdn.example.com/other.css"`) {
		t.Errorf("external stylesheet must stay absolute:\n%s", out)
	}
}

func TestProxyRewriteCSS(t *testing.T) {
	base, _ := url.Parse("https://sso.example.com/css/main.css")
	css := []byte(`body{background:url(/img/bg.png)}@font-face{src:url(https://sso.example.com/f.woff2)}a{background:url(https://cdn.example.com/x.png)}`)
	out := string(ProxyRewriteCSS(css, base, proxyTestPrefix))
	if !strings.Contains(out, `url("/l/ab12/px/img/bg.png")`) {
		t.Errorf("root-absolute url not rewritten: %s", out)
	}
	if !strings.Contains(out, `url("/l/ab12/px/f.woff2")`) {
		t.Errorf("same-origin absolute url not rewritten: %s", out)
	}
	if !strings.Contains(out, `url(https://cdn.example.com/x.png)`) {
		t.Errorf("external url must stay: %s", out)
	}
}

func TestProxyShimEmbedsPrefix(t *testing.T) {
	js := ProxyShimJS("/l/zz/px/")
	if !strings.Contains(js, `"/l/zz/px/"`) {
		t.Fatalf("shim does not embed the prefix: %s", js)
	}
	for _, want := range []string{"MutationObserver", "navigator.serviceWorker", "history.pushState", "sendBeacon"} {
		if !strings.Contains(js, want) {
			t.Errorf("shim missing %s", want)
		}
	}
}
