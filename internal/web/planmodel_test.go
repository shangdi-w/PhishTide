package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLLMPlanModelSetting(t *testing.T) {
	s := newAgentServer(t)
	body := bytes.NewBufferString(`{"base_url":"http://127.0.0.1:11434/v1","model":"fast","plan_model":"reasoner","temperature":0.7}`)
	rr := httptest.NewRecorder()
	s.adminLLMConfig(rr, httptest.NewRequest(http.MethodPost, "/__admin/api/llm", body))
	if rr.Code != 200 {
		t.Fatalf("save status = %d body=%s", rr.Code, rr.Body.String())
	}
	s.settingsMu.Lock()
	s.settingsLoaded = false
	s.settingsMu.Unlock()
	if got := s.planModel(); got != "reasoner" {
		t.Fatalf("planModel = %q", got)
	}
	rr = httptest.NewRecorder()
	s.adminLLMConfig(rr, httptest.NewRequest(http.MethodGet, "/__admin/api/llm", nil))
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["plan_model"] != "reasoner" {
		t.Fatalf("GET plan_model = %v", out["plan_model"])
	}
}
