package email

import (
	"strings"
	"testing"
)

func TestHTMLToText(t *testing.T) {
	in := `<html><head><style>.x{color:red}</style></head><body>
		<p>你好 <b>张三</b>，请<a href="https://x">点击这里</a>。</p>
		<div>验证码：<span>123456</span></div>
		<script>alert(1)</script>
	</body></html>`
	out := HTMLToText(in)
	for _, want := range []string{"你好", "张三", "点击这里", "验证码", "123456"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
	for _, bad := range []string{"<", "alert(1)", "color:red"} {
		if strings.Contains(out, bad) {
			t.Fatalf("unexpected %q in %q", bad, out)
		}
	}
	if strings.Contains(out, "\n\n\n") {
		t.Fatalf("blank lines not collapsed: %q", out)
	}
}

func TestPrepareHTMLAddsHintsOnce(t *testing.T) {
	in := `<html><head><title>x</title></head><body><p>x</p></body></html>`
	out := PrepareHTML(in)
	if !strings.Contains(out, `name="viewport"`) || !strings.Contains(out, `color-scheme" content="light only`) {
		t.Fatalf("hints missing: %q", out)
	}
	again := PrepareHTML(out)
	if strings.Count(strings.ToLower(again), `name="viewport"`) != 1 || strings.Count(strings.ToLower(again), `name="color-scheme"`) != 1 {
		t.Fatalf("hints duplicated: %q", again)
	}
	if PrepareHTML("") != "" {
		t.Fatal("empty body should stay empty")
	}
}
