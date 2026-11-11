package web

// Per-page language/brand copy: the "wrong password" message must follow the
// page, not a hardcoded Chinese string.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"phishsim/internal/core/store"
)

func TestPatchPageReplacesAndInjectsCSS(t *testing.T) {
	s := newAgentServer(t)
	sid, _ := s.Store.CreateChatSession("")
	id, err := s.Store.UpsertPage(store.LandingPage{
		Name: "补丁页", Kind: "template",
		Body:        `<html><head><title>旧标题</title></head><body><form action="__SUBMIT_URL__"><input name="user"></form></body></html>`,
		ContentType: "text/html; charset=utf-8",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, ok, _ := execToolCtx(t, s, runCtx(), sid, "patch_page", map[string]any{
		"page_id": id, "find": "旧标题", "replace": "新标题", "css": "body{color:#111}",
	})
	if !ok {
		t.Fatalf("patch failed: %+v", out)
	}
	p, _ := s.Store.GetPage(id)
	if strings.Contains(p.Body, "旧标题") || !strings.Contains(p.Body, "新标题") {
		t.Fatalf("replacement not applied: %s", p.Body)
	}
	if !strings.Contains(p.Body, `data-hp-patch="1"`) {
		t.Fatalf("css not injected: %s", p.Body)
	}

	s.resetRunWrites(sid)
	if _, ok, _ := execToolCtx(t, s, runCtx(), sid, "patch_page", map[string]any{
		"page_id": id, "find": "不存在的文本", "replace": "x",
	}); ok {
		t.Fatal("missing find should fail")
	}
}

func TestRetryMessageAutoDetectsLanguage(t *testing.T) {
	en := store.LandingPage{Body: `<html><body><h1>Sign in</h1></body></html>`}
	if got := retryMessage(en); !strings.Contains(got, "Incorrect username or password") {
		t.Fatalf("english page fallback = %q", got)
	}
	zh := store.LandingPage{Body: `<html><body><h1>登录</h1></body></html>`}
	if got := retryMessage(zh); !strings.Contains(got, "用户名或密码错误") {
		t.Fatalf("chinese page fallback = %q", got)
	}
	custom := store.LandingPage{Body: "<html/>", ErrorMessage: "Credenciales incorrectas."}
	if got := retryMessage(custom); got != "Credenciales incorrectas." {
		t.Fatalf("explicit message lost: %q", got)
	}
}

func TestRenderRetryUsesPageMessage(t *testing.T) {
	page := `<html><body><form action="__SUBMIT_URL__"><input name="user"></form></body></html>`
	out := renderRetry(page, "/l/x", "alice", "Incorrect username or password. Please try again.")
	if !strings.Contains(out, "Incorrect username or password. Please try again.") {
		t.Fatalf("custom message missing:\n%s", out)
	}
	if strings.Contains(out, "用户名或密码错误") {
		t.Fatalf("default Chinese banner leaked into an English page")
	}
	// Blank falls back to the built-in Chinese prompt.
	out = renderRetry(page, "/l/x", "alice", "")
	if !strings.Contains(out, "用户名或密码错误") {
		t.Fatalf("default banner missing")
	}
}

func TestProxyFakeLoginUsesPageMessage(t *testing.T) {
	s := newAgentServer(t)
	page := store.LandingPage{Name: "English portal", Kind: "proxy", SourceURL: "https://example.com",
		ErrorMessage: "Incorrect username or password. Please try again."}

	// HTML retry page.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/l/x/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	s.proxyFakeLogin(rr, req, page, true, true)
	body := rr.Body.String()
	if !strings.Contains(body, "Incorrect username or password. Please try again.") || !strings.Contains(body, ">Back<") {
		t.Fatalf("proxy retry html not localised:\n%s", body)
	}
	if strings.Contains(body, "用户名或密码错误") {
		t.Fatalf("Chinese copy leaked into English proxy page")
	}

	// JSON login API.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/l/x/api/login", nil)
	req.Header.Set("Accept", "application/json")
	s.proxyFakeLogin(rr, req, page, true, true)
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["message"] != page.ErrorMessage {
		t.Fatalf("json message = %v", out["message"])
	}

	// Success screen (no redirect configured).
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/l/x/", nil)
	req.Header.Set("Accept", "text/html")
	s.proxyFakeLogin(rr, req, page, false, true)
	if !strings.Contains(rr.Body.String(), "You can close this page.") {
		t.Fatalf("success screen not localised:\n%s", rr.Body.String())
	}
}

func TestLandingPageErrorMessageRoundTrip(t *testing.T) {
	s := newAgentServer(t)
	id, err := s.Store.UpsertPage(store.LandingPage{
		Name: "英文门户", Kind: "template",
		Body:         `<form action="__SUBMIT_URL__"><input name="user"><input type="password" name="pass"></form>`,
		ContentType:  "text/html; charset=utf-8",
		ErrorMessage: "Invalid credentials, please try again.",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Store.GetPage(id)
	if err != nil || p.ErrorMessage != "Invalid credentials, please try again." {
		t.Fatalf("GetPage = %+v err=%v", p, err)
	}
	list, _ := s.Store.ListPages()
	if len(list) != 1 || list[0].ErrorMessage != p.ErrorMessage {
		t.Fatalf("ListPages = %+v", list)
	}
}

func TestLandingCheckWarnsWhenMessageMissing(t *testing.T) {
	body := `<html><body><form action="__SUBMIT_URL__"><input name="user"><input type="password" name="pass"></form></body></html>`
	c := checkLandingPage(store.LandingPage{Name: "p", Kind: "template", Body: body})
	found := false
	for _, w := range c.Warnings {
		if strings.Contains(w, "error_message") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing warning: %+v", c.Warnings)
	}
	c = checkLandingPage(store.LandingPage{Name: "p", Kind: "template", Body: body, ErrorMessage: "密码错误"})
	for _, w := range c.Warnings {
		if strings.Contains(w, "error_message") {
			t.Fatalf("warning should disappear when set: %+v", c.Warnings)
		}
	}
}

func TestCreateLandingPageStoresErrorMessage(t *testing.T) {
	s := newAgentServer(t)
	sid, _ := s.Store.CreateChatSession("")
	out, ok, _ := execToolCtx(t, s, runCtx(), sid, "create_landing_page", map[string]any{
		"name":          "英文登录页",
		"html":          `<html><body><form action="__SUBMIT_URL__"><input name="username"><input type="password" name="password"></form></body></html>`,
		"error_message": "Incorrect username or password. Please try again.",
	})
	if !ok {
		t.Fatalf("create failed: %+v", out)
	}
	id := int64(out["page_id"].(float64))
	p, err := s.Store.GetPage(id)
	if err != nil || p.ErrorMessage != "Incorrect username or password. Please try again." {
		t.Fatalf("stored error_message = %q err=%v", p.ErrorMessage, err)
	}
}
