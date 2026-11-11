// clone_probe exercises the site cloner against one URL and prints a fidelity
// summary. It is a development tool for the authorized targets of this
// platform, not part of the server binary.
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"phishsim/internal/features/clone"
)

func main() {
	url := flag.String("url", "", "target URL")
	mode := flag.String("mode", "render", "render (headless browser) or fetch")
	static := flag.Bool("static", false, "static form transform (strip JS)")
	spa := flag.Bool("spa", true, "SPA shim when not static")
	assets := flag.Bool("assets", true, "mirror same-origin assets")
	out := flag.String("out", "clone-probe.html", "output HTML path")
	timeout := flag.Duration("timeout", 45*time.Second, "timeout")
	assetDir := flag.String("assetdir", "", "write mirrored assets under this directory")
	netCapture := flag.Bool("net", false, "record the browser's network and replay XHR/fetch JSON")
	flag.Parse()
	if *url == "" {
		fmt.Fprintln(os.Stderr, "-url required")
		os.Exit(2)
	}

	opts := clone.Options{
		URL:          *url,
		Timeout:      *timeout,
		MirrorAssets: *assets,
		StaticForm:   *static,
		SPAShim:      *spa,
		CaptureNet:   *netCapture,
	}
	start := time.Now()
	var res *clone.Result
	var err error
	if *mode == "render" {
		res, err = clone.CloneWithBrowser(opts)
	} else {
		res, err = clone.Clone(opts)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "clone failed: %v\n", err)
		os.Exit(1)
	}
	body := string(res.Body)
	if err := os.WriteFile(*out, res.Body, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("final_url:   %s\n", res.FinalURL)
	fmt.Printf("content:     %s\n", res.ContentType)
	fmt.Printf("spa:         %v\n", res.SPA)
	fmt.Printf("assets:      %d\n", len(res.Assets))
	fmt.Printf("body_bytes:  %d\n", len(res.Body))
	fmt.Printf("has_form:    %v\n", strings.Contains(strings.ToLower(body), "<form"))
	fmt.Printf("password:    %v\n", regexp.MustCompile(`(?i)type\s*=\s*["']?password`).MatchString(body))
	fmt.Printf("script_tags: %d\n", strings.Count(strings.ToLower(body), "<script"))
	fmt.Printf("static_shim: %v\n", strings.Contains(body, "data-hp-static-form"))
	fmt.Printf("spa_shim:    %v\n", strings.Contains(body, "data-hp-clone"))
	fmt.Printf("elapsed:     %s\n", time.Since(start).Round(time.Millisecond))

	// Same-origin references that stayed absolute often mean a mirror miss.
	for _, host := range externalHosts(body) {
		fmt.Printf("ext_ref:     %s\n", host)
	}
	for _, a := range res.Assets {
		fmt.Printf("asset:       %s -> %s (%d bytes)\n", a.URL, a.Path, len(a.Body))
		if *assetDir == "" {
			continue
		}
		rel := strings.TrimPrefix(a.Path, "/")
		dst := *assetDir + string(os.PathSeparator) + strings.ReplaceAll(rel, "/", string(os.PathSeparator))
		dir := dst
		if i := strings.LastIndexByte(dst, os.PathSeparator); i >= 0 {
			dir = dst[:i]
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			continue
		}
		_ = os.WriteFile(dst, a.Body, 0o644)
	}
}

var absURL = regexp.MustCompile(`(?i)(?:src|href|action)\s*=\s*["'](https?://[^"'/]+)`)

func externalHosts(body string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range absURL.FindAllStringSubmatch(body, -1) {
		h := strings.ToLower(m[1])
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}
