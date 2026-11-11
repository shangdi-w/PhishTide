package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"phishsim/internal/core/store"
)

func TestSearchAPIRedactsSecrets(t *testing.T) {
	s := newAgentServer(t)
	_ = s.Store.RecordSendLedger(store.SendLedgerEntry{
		CampaignName: "c", Email: "a@example.com", Subject: "token=abc123", Status: "sent",
	})
	rr := httptest.NewRecorder()
	s.adminSearch(rr, httptest.NewRequest(http.MethodGet, "/__admin/api/search?q=token", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "abc123") {
		t.Fatalf("secret leaked: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "ledger") {
		t.Fatalf("ledger hit missing: %s", rr.Body.String())
	}
}

func TestBulkSuppressionAPI(t *testing.T) {
	s := newAgentServer(t)
	body := bytes.NewBufferString(`{"text":"a@example.com\nb@example.com\nbad","reason":"manual"}`)
	rr := httptest.NewRecorder()
	s.adminBulkSuppress(rr, httptest.NewRequest(http.MethodPost, "/__admin/api/suppressions/bulk", body))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"added":2`) {
		t.Fatalf("bulk = %d %s", rr.Code, rr.Body.String())
	}
	list, _ := s.Store.ListSuppressions(10)
	if len(list) != 2 {
		t.Fatalf("list = %+v", list)
	}
}
