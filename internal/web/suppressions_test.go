package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"phishsim/internal/core/store"
)

func TestSuppressionAPI(t *testing.T) {
	s := newAgentServer(t)
	body := bytes.NewBufferString(`{"email":"Victim@Example.com","reason":"manual","note":"test"}`)
	rr := httptest.NewRecorder()
	s.adminSuppressions(rr, httptest.NewRequest(http.MethodPost, "/__admin/api/suppressions", body))
	if rr.Code != 200 {
		t.Fatalf("add = %d %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	s.adminSuppressions(rr, httptest.NewRequest(http.MethodGet, "/__admin/api/suppressions", nil))
	var out struct {
		Suppressions []store.Suppression `json:"suppressions"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Suppressions) != 1 || out.Suppressions[0].Email != "victim@example.com" {
		t.Fatalf("list = %+v", out)
	}
	rr = httptest.NewRecorder()
	s.adminDeleteSuppression(rr, httptest.NewRequest(http.MethodPost, "/__admin/api/suppressions/delete",
		strings.NewReader(`{"email":"victim@example.com"}`)))
	if rr.Code != 200 {
		t.Fatalf("delete = %d", rr.Code)
	}
}

func TestSendSkipsSuppressedRecipient(t *testing.T) {
	s := newAgentServer(t)
	tid, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	pid, _ := s.Store.UpsertPage(store.LandingPage{Name: "p", Kind: "template", Body: "<form></form>"}, nil)
	gid, _ := s.Store.CreateGroup("g")
	_, _ = s.Store.AddTargetsToGroup(gid, []store.Target{{Email: "a@example.com"}})
	cid, _ := s.Store.CreateCampaign(store.Campaign{Name: "c", EmailTemplateID: tid, LandingPageID: pid}, []int64{gid})
	_ = s.Store.UpsertSuppression("a@example.com", "manual", "")
	out, err := s.sendCampaignEmail(cid, 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if out.Suppressed != 1 || out.Total != 1 || out.Sent != 0 {
		t.Fatalf("outcome = %+v", out)
	}
}
