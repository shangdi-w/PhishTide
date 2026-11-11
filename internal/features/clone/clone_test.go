package clone

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestCloneRewritesFormAndAssets verifies the stripped cloner still rewrites a
// form action to the capture placeholder and mirrors same-origin assets.
func TestCloneRewritesFormAndAssets(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head><link rel="stylesheet" href="/style.css"></head>
<body><form method="post" action="/login">
<input name="username"><input name="password" type="password"><button>go</button>
</form></body></html>`))
	})
	mux.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write([]byte("body{color:red}"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := Clone(Options{
		URL:          srv.URL + "/login",
		BaseURL:      "https://phish.example.com",
		MirrorAssets: true,
		AssetPrefix:  "/__assets__/",
		FormAction:   "/__submit__",
	})
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	body := string(res.Body)
	if !strings.Contains(body, `action="/__submit__"`) {
		t.Errorf("form action not rewritten; body:\n%s", body)
	}
	if !strings.Contains(body, "/__assets__/") {
		t.Errorf("asset reference not rewritten; body:\n%s", body)
	}
	if len(res.Assets) != 1 {
		t.Errorf("expected 1 mirrored asset, got %d", len(res.Assets))
	}
}

// TestCloneNonHTML verifies non-HTML/non-JSON targets are rejected.
func TestCloneNonHTML(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/img.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte{0x89, 'P', 'N', 'G'})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if _, err := Clone(Options{URL: srv.URL + "/img.png"}); err == nil {
		t.Fatal("expected error for non-HTML/JSON target")
	}
}

func TestCollectAssetsHonoursBaseTagAndSrcset(t *testing.T) {
	base, _ := url.Parse("https://example.com/app/index.html")
	doc := []byte(`<html><head><base href="/static/"></head><body>
<img src="logo.png" srcset="logo@2x.png 2x, logo@3x.png 3x" data-src="lazy.jpg">
</body></html>`)
	got := collectAssetURLs(base, doc, 0)
	want := map[string]bool{
		"https://example.com/static/logo.png":    false,
		"https://example.com/static/logo@2x.png": false,
		"https://example.com/static/logo@3x.png": false,
		"https://example.com/static/lazy.jpg":    false,
	}
	for _, u := range got {
		if _, ok := want[u]; ok {
			want[u] = true
		}
	}
	for u, seen := range want {
		if !seen {
			t.Errorf("missing asset %s (got %v)", u, got)
		}
	}
}
