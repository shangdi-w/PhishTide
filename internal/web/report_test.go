package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"phishsim/internal/core/store"
	"phishsim/internal/services/report"
)

func TestAdminReportServesJSONAndHTML(t *testing.T) {
	s := newAgentServer(t)
	tpl, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	page, _ := s.Store.UpsertPage(store.LandingPage{Name: "p", Kind: "template", Body: "<p>x</p>"}, nil)
	gid, _ := s.Store.CreateGroup("g")
	_, _ = s.Store.AddTargetsToGroup(gid, []store.Target{
		{Email: "a@example.com", Department: "研发部"},
		{Email: "b@example.com", Department: "财务部"},
	})
	camp, err := s.Store.CreateCampaign(store.Campaign{Name: "c", EmailTemplateID: tpl, LandingPageID: page}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	results, _ := s.Store.ListResults(camp)
	s.Store.MarkOpened(results[0], "1.2.3.4", "ua", "")
	s.Store.MarkClicked(results[0], "1.2.3.4", "ua", "")
	s.Store.MarkReported(results[1], "1.2.3.5", "ua", "")

	rr := httptest.NewRecorder()
	s.adminReport(rr, httptest.NewRequest(http.MethodGet, "/__admin/api/report?campaign_id=1", nil))
	if rr.Code != 200 {
		t.Fatalf("json status = %d body=%s", rr.Code, rr.Body.String())
	}
	var rep report.Report
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Totals.Users != 2 || rep.Totals.Clicked != 1 || rep.Departments[0].Department != "研发部" {
		t.Fatalf("unexpected report: %+v", rep)
	}

	rr = httptest.NewRecorder()
	s.adminReport(rr, httptest.NewRequest(http.MethodGet, "/__admin/api/report?campaign_id=1&format=html", nil))
	if rr.Code != 200 || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("html response = %d %q", rr.Code, rr.Header().Get("Content-Type"))
	}
	if !strings.Contains(rr.Body.String(), "a@example.com") || !strings.Contains(rr.Body.String(), "研发部") {
		t.Fatal("html report misses data")
	}
}

func TestAdminReportRejectsMissingCampaign(t *testing.T) {
	s := newAgentServer(t)
	rr := httptest.NewRecorder()
	s.adminReport(rr, httptest.NewRequest(http.MethodGet, "/__admin/api/report", nil))
	if rr.Code != 400 {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestAdminGroupAuditFlagsRoleAndDuplicates(t *testing.T) {
	s := newAgentServer(t)
	gid, _ := s.Store.CreateGroup("g")
	_, _ = s.Store.AddTargetsToGroup(gid, []store.Target{
		{Email: "a@example.com"},
		{Email: "A@example.com"},
		{Email: "admin@example.com"},
	})
	rr := httptest.NewRecorder()
	s.adminGroupAudit(rr, httptest.NewRequest(http.MethodGet, "/__admin/api/groups/1/audit?mx=0", nil), gid)
	if rr.Code != 200 {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		Total  int            `json:"total"`
		Unique int            `json:"unique"`
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 3 || out.Unique != 2 || out.Counts["duplicate"] != 1 || out.Counts["role"] != 1 {
		t.Fatalf("audit = %+v", out)
	}
}

func TestAuditGroupTool(t *testing.T) {
	s := newAgentServer(t)
	gid, _ := s.Store.CreateGroup("g")
	_, _ = s.Store.AddTargetsToGroup(gid, []store.Target{
		{Email: "info@example.com"},
		{Email: "bob@mailinator.com"},
	})
	out, ok, note := execTool(t, s, 0, "audit_group", map[string]any{"group_id": gid, "check_mx": false})
	if !ok {
		t.Fatalf("audit_group failed: %v", note)
	}
	if out["counts"].(map[string]any)["role"].(float64) != 1 ||
		out["counts"].(map[string]any)["disposable"].(float64) != 1 {
		t.Fatalf("unexpected audit output: %+v", out)
	}
}

func TestRiskReportTool(t *testing.T) {
	s := newAgentServer(t)
	tpl, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	page, _ := s.Store.UpsertPage(store.LandingPage{Name: "p", Kind: "template", Body: "<p>x</p>"}, nil)
	gid, _ := s.Store.CreateGroup("g")
	_, _ = s.Store.AddTargetsToGroup(gid, []store.Target{
		{Email: "a@example.com", Department: "研发部"},
		{Email: "b@example.com", Department: "研发部"},
	})
	camp, _ := s.Store.CreateCampaign(store.Campaign{Name: "c", EmailTemplateID: tpl, LandingPageID: page}, []int64{gid})
	results, _ := s.Store.ListResults(camp)
	s.Store.MarkOpened(results[0], "1.2.3.4", "ua", "")
	s.Store.MarkClicked(results[0], "1.2.3.4", "ua", "")
	_ = s.Store.RecordSubmission(results[0], "1.2.3.4", "ua", "", "a", "pw", map[string][]string{"password": {"pw"}})

	out, ok, _ := execTool(t, s, 0, "risk_report", map[string]any{"campaign_id": camp})
	if !ok {
		t.Fatalf("risk_report failed: %s", out)
	}
	totals := out["totals"].(map[string]any)
	if totals["high_risk"].(float64) != 1 || totals["submitted"].(float64) != 1 {
		t.Fatalf("unexpected totals: %+v", totals)
	}
	url, _ := out["report_url"].(string)
	if !strings.Contains(url, "campaign_id=") || !strings.Contains(url, "format=html") {
		t.Fatalf("report_url = %q", url)
	}
}

func TestPreviewPageToolRendersScreenshot(t *testing.T) {
	if os.Getenv("PHISH_TEST_RENDER") != "1" {
		t.Skip("set PHISH_TEST_RENDER=1 with Chrome installed to run the screenshot test")
	}
	s := newAgentServer(t)
	page, _ := s.Store.UpsertPage(store.LandingPage{
		Name: "p", Kind: "template", ContentType: "text/html; charset=utf-8",
		Body:               `<!doctype html><html><head><title>Login</title></head><body style="background:#0b57d0"><h1>Sign in</h1><form action="__SUBMIT_URL__"><input name="email"><input type="password" name="password"></form></body></html>`,
		CaptureCredentials: true, CapturePasswords: true,
	}, nil)
	out, ok, note := execTool(t, s, 0, "preview_page", map[string]any{"page_id": page})
	if !ok {
		t.Fatalf("preview_page failed: %v", note)
	}
	if out["width"].(float64) <= 0 || out["height"].(float64) <= 0 || out["bytes"].(float64) == 0 {
		t.Fatalf("unexpected screenshot metadata: %+v", out)
	}
}
