package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"phishsim/internal/core/config"
	"phishsim/internal/core/store"
	"phishsim/internal/features/llm"
)

func TestTrimChatHistoryKeepsTail(t *testing.T) {
	var msgs []llm.Message
	for i := 0; i < 100; i++ {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		msgs = append(msgs, llm.Message{Role: role, Content: "x"})
	}
	out := trimChatHistory(msgs, 10, 1000)
	if len(out) != 10 {
		t.Fatalf("kept %d messages, want 10", len(out))
	}
	if out[len(out)-1].Content != msgs[len(msgs)-1].Content {
		t.Fatal("newest message was dropped")
	}
	if out[0].Role != msgs[len(msgs)-10].Role || out[0].Content != msgs[len(msgs)-10].Content {
		t.Fatal("kept the wrong window")
	}
}

func TestTrimChatHistoryAlwaysKeepsLast(t *testing.T) {
	msgs := []llm.Message{
		{Role: "user", Content: strings.Repeat("中", 50000)},
		{Role: "assistant", Content: "ok"},
		{Role: "user", Content: "最新问题"},
	}
	out := trimChatHistory(msgs, 40, 100)
	if len(out) != 1 || out[0].Content != "最新问题" {
		t.Fatalf("out = %+v", out)
	}
}

func TestTrimChatHistoryDropsLeadingAssistant(t *testing.T) {
	msgs := []llm.Message{
		{Role: "assistant", Content: "old reply"},
		{Role: "user", Content: "q"},
		{Role: "assistant", Content: "a"},
	}
	out := trimChatHistory(msgs, 40, 1000)
	if len(out) != 2 || out[0].Role != "user" {
		t.Fatalf("out = %+v", out)
	}
}

func newConfigStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	st.SetSecretKey([]byte("01234567890123456789012345678901"))
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestRestoreLLMConfigFromSavedSettings(t *testing.T) {
	st := newConfigStore(t)
	if err := st.SetSetting(settingLLMBaseURL, "http://127.0.0.1:11434/v1"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(settingLLMModel, "saved-model"); err != nil {
		t.Fatal(err)
	}
	enc := st.EncryptSetting("saved-key")
	if !strings.HasPrefix(enc, "enc:v1:") {
		t.Fatalf("key not sealed: %q", enc)
	}
	if err := st.SetSetting(settingLLMKey, enc); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		Cfg:   &config.Config{LLMModel: "deepseek-flash"},
		Store: st,
		LLM:   llm.New("", "", "deepseek-flash"),
	}
	s.RestoreLLMConfig()
	cli := s.getLLM()
	if cli.BaseURL != "http://127.0.0.1:11434/v1" {
		t.Fatalf("base_url = %q", cli.BaseURL)
	}
	if cli.Model != "saved-model" {
		t.Fatalf("saved model lost to default, got %q", cli.Model)
	}
	if cli.Key != "saved-key" {
		t.Fatalf("saved key not restored, got %q", cli.Key)
	}
}

func TestRestoreLLMConfigTemperature(t *testing.T) {
	st := newConfigStore(t)
	if err := st.SetSetting(settingLLMBaseURL, "http://127.0.0.1:11434/v1"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(settingLLMTemperature, "0.2"); err != nil {
		t.Fatal(err)
	}

	s := &Server{Cfg: &config.Config{}, Store: st}
	s.RestoreLLMConfig()
	if got := s.getLLM().Temperature; got != 0.2 {
		t.Fatalf("saved temperature = %v, want 0.2", got)
	}

	// An explicit deployment value wins over the saved one.
	s2 := &Server{
		Cfg:   &config.Config{LLMTemperature: 1.5, LLMTemperatureSet: true},
		Store: st,
	}
	s2.RestoreLLMConfig()
	if got := s2.getLLM().Temperature; got != 1.5 {
		t.Fatalf("explicit env temperature should win, got %v", got)
	}
}

func TestAllowLLMCallIsPerSession(t *testing.T) {
	s := &Server{}
	req := func(cookie string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/__admin/api/chat", nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "phish_admin", Value: cookie})
		}
		return r
	}
	// Session A exhausts its budget.
	for i := 0; i < 3; i++ {
		if !s.allowLLMCall(req("session-a"), 3) {
			t.Fatalf("call %d for session A unexpectedly denied", i+1)
		}
	}
	if s.allowLLMCall(req("session-a"), 3) {
		t.Fatal("session A should be rate limited")
	}
	// Session B is unaffected by A's usage.
	if !s.allowLLMCall(req("session-b"), 3) {
		t.Fatal("session B should have its own budget")
	}
	// Rate 0 disables the limiter.
	for i := 0; i < 100; i++ {
		if !s.allowLLMCall(req("session-a"), 0) {
			t.Fatal("rate 0 should be unlimited")
		}
	}
}

func TestAdminLLMConfigTemperature(t *testing.T) {
	st := newConfigStore(t)
	s := &Server{
		Cfg:   &config.Config{},
		Store: st,
		LLM:   llm.New("http://127.0.0.1:11434/v1", "", "m"),
	}

	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/__admin/api/llm", strings.NewReader(body))
		s.adminLLMConfig(rr, r)
		return rr
	}

	if rr := post(`{"base_url":"http://127.0.0.1:11434/v1","model":"m","temperature":0.2}`); rr.Code != http.StatusOK {
		t.Fatalf("valid save: status %d body %s", rr.Code, rr.Body.String())
	}
	if got := s.getLLM().Temperature; got != 0.2 {
		t.Fatalf("in-memory temperature = %v, want 0.2", got)
	}
	m, err := st.SettingsMap()
	if err != nil {
		t.Fatalf("settings map: %v", err)
	}
	if got := m[settingLLMTemperature]; got != "0.2" {
		t.Fatalf("persisted temperature = %q, want 0.2", got)
	}

	if rr := post(`{"base_url":"http://127.0.0.1:11434/v1","temperature":3}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("out-of-range temperature should be rejected, got %d", rr.Code)
	}

	// A restart restores the saved temperature.
	s2 := &Server{Cfg: &config.Config{}, Store: st}
	s2.RestoreLLMConfig()
	if got := s2.getLLM().Temperature; got != 0.2 {
		t.Fatalf("temperature after restart = %v, want 0.2", got)
	}
}

func TestRestoreLLMConfigExplicitEnvModelWins(t *testing.T) {
	st := newConfigStore(t)
	if err := st.SetSetting(settingLLMBaseURL, "http://127.0.0.1:11434/v1"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(settingLLMModel, "saved-model"); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		Cfg:   &config.Config{LLMModel: "env-model", LLMModelSet: true},
		Store: st,
		LLM:   llm.New("", "", "env-model"),
	}
	s.RestoreLLMConfig()
	if got := s.getLLM().Model; got != "env-model" {
		t.Fatalf("explicit env model should win, got %q", got)
	}
}
