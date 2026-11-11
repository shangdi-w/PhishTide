package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"phishsim/internal/core/store"
)

func TestUploadImagesBuildsDataURLs(t *testing.T) {
	s := newAgentServer(t)
	sid, _ := s.Store.CreateChatSession("")
	_, _ = s.Store.AddChatUpload(store.ChatUpload{SessionID: sid, Name: "shot.png", ContentType: "image/png", Body: []byte{0x89, 'P', 'N', 'G'}})
	_, _ = s.Store.AddChatUpload(store.ChatUpload{SessionID: sid, Name: "list.csv", ContentType: "text/csv", Body: []byte("a@example.com")})
	imgs := s.uploadImages(sid)
	if len(imgs) != 1 || !strings.HasPrefix(imgs[0], "data:image/png;base64,") {
		t.Fatalf("images = %+v", imgs)
	}
}

func TestFetchAllowlist(t *testing.T) {
	t.Setenv("PHISH_FETCH_ALLOWLIST", "example.com, *.trusted.test")
	s := newAgentServer(t)
	if !s.fetchAllowed("example.com") || !s.fetchAllowed("sub.example.com:8443") || !s.fetchAllowed("a.trusted.test") {
		t.Fatal("allowed host rejected")
	}
	if s.fetchAllowed("evil.com") || s.fetchAllowed("example.com.evil.com") {
		t.Fatal("disallowed host accepted")
	}
}

func TestAgentSystemPromptPrioritisesRelevantMemory(t *testing.T) {
	s := newAgentServer(t)
	if err := s.Store.UpsertAgentMemory("发件邮箱", "ops@example.com", "preference"); err != nil {
		t.Fatal(err)
	}
	p := s.agentSystemPrompt("发件邮箱用哪个？")
	if !strings.Contains(p, "[偏好] 发件邮箱") || !strings.Contains(p, "ops@example.com") {
		t.Fatalf("relevant memory missing from prompt: %s", p)
	}
}

func TestUploadPDFTextAndSanitize(t *testing.T) {
	s := newAgentServer(t)
	sid, _ := s.Store.CreateChatSession("")
	pdf := []byte("%PDF-1.4\nstream\nBT (PDF body text) Tj ET\nendstream")
	_, _ = s.Store.AddChatUpload(store.ChatUpload{SessionID: sid, Name: "说明.pdf", ContentType: "application/pdf", Body: pdf})
	texts := s.uploadTexts(sid)
	if len(texts) != 1 || !strings.Contains(texts[0], "PDF body text") {
		t.Fatalf("texts = %+v", texts)
	}
	if again := s.uploadTexts(sid); len(again) != 0 {
		t.Fatalf("pdf text injected twice: %+v", again)
	}
	clean := sanitizeExternalHTML(`<html><script>evil()</script><!-- hidden --><body>ok</body></html>`)
	if strings.Contains(clean, "evil") || strings.Contains(clean, "hidden") || !strings.Contains(clean, "ok") {
		t.Fatalf("sanitize = %q", clean)
	}
}

func TestTaintedHighRiskAlwaysGates(t *testing.T) {
	s := newAgentServer(t)
	sid, _ := s.Store.CreateChatSession("")
	s.grantSessionApproval(sid)
	s.markTainted(sid)
	out, ok, _ := execToolCtx(t, s, runCtx(), sid, "create_sending_profile", map[string]any{
		"name": "注入后账号", "username": "x@example.com", "password": "p",
	})
	if !ok || out["status"] != "awaiting_user_confirmation" {
		t.Fatalf("tainted high-risk should gate even with approval: %+v", out)
	}
	if list, _ := s.Store.ListSendingProfiles(); len(list) != 0 {
		t.Fatalf("profile created: %+v", list)
	}
}

func TestSessionRunLock(t *testing.T) {
	s := newAgentServer(t)
	if !s.acquireSessionRun(1) {
		t.Fatal("first acquire failed")
	}
	if s.acquireSessionRun(1) {
		t.Fatal("second concurrent acquire should fail")
	}
	s.releaseSessionRun(1)
	if !s.acquireSessionRun(1) {
		t.Fatal("acquire after release failed")
	}
	s.releaseSessionRun(1)
}

func TestGlobalAgentMetricsAPI(t *testing.T) {
	s := newAgentServer(t)
	sid, _ := s.Store.CreateChatSession("会话甲")
	_ = s.Store.MergeAgentMetrics(sid, 2, 4, 1, 900, 10, 20, 30)
	rr := httptest.NewRecorder()
	s.adminAgentGlobalMetrics(rr, httptest.NewRequest(http.MethodGet, "/__admin/api/agent/metrics/global", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d", rr.Code)
	}
	var out struct {
		Totals   map[string]any   `json:"totals"`
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Totals["runs"].(float64) != 1 || out.Totals["total_tokens"].(float64) != 30 || len(out.Sessions) != 1 {
		t.Fatalf("global = %+v", out)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	t.Setenv("PHISH_METRICS_TOKEN", "tok")
	s := newAgentServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer tok")
	s.handleMetrics(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "phishsim_up 1") {
		t.Fatalf("metrics = %d %s", rr.Code, rr.Body.String()[:200])
	}
	rr = httptest.NewRecorder()
	s.handleMetrics(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated metrics = %d", rr.Code)
	}
}
