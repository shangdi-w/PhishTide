package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"phishsim/internal/core/store"
	"phishsim/internal/services/analyze"
	"phishsim/internal/services/geoip"
)

func loadTestGeoDB(t *testing.T) *geoip.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ip2asn.tsv")
	body := "114.114.0.0\t114.114.255.255\t4134\tCN\tCHINANET-BACKBONE\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := geoip.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestSubmissionsAreGeoEnriched(t *testing.T) {
	s := newAgentServer(t)
	s.Geo = loadTestGeoDB(t)

	tpl, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	page, _ := s.Store.UpsertPage(store.LandingPage{Name: "p", Kind: "template", Body: "<p>x</p>"}, nil)
	gid, _ := s.Store.CreateGroup("g")
	if _, err := s.Store.AddTargetsToGroup(gid, []store.Target{{Email: "victim@example.com"}}); err != nil {
		t.Fatal(err)
	}
	cid, err := s.Store.CreateCampaign(store.Campaign{Name: "c", EmailTemplateID: tpl, LandingPageID: page}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	results, _ := s.Store.ListResults(cid)
	if len(results) != 1 {
		t.Fatalf("results = %d", len(results))
	}
	s.Store.MarkSent(results[0].ID)
	if err := s.Store.RecordSubmission(results[0], "114.114.114.114", "ua", "", "user1", "pw", nil); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	s.adminSubmissions(rr, httptest.NewRequest(http.MethodGet, "/", nil), cid)
	if rr.Code != 200 {
		t.Fatalf("handler = %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Submissions []store.Submission `json:"submissions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Submissions) != 1 {
		t.Fatalf("submissions = %+v", out.Submissions)
	}
	sub := out.Submissions[0]
	if sub.Country != "中国" || sub.Org != "CHINANET-BACKBONE" {
		t.Fatalf("geo not enriched: %+v", sub)
	}

	rr = httptest.NewRecorder()
	s.adminSubmissionsExport(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(rr.Body.String(), "ip,country,org") {
		t.Fatalf("export header missing geo columns: %q", strings.SplitN(rr.Body.String(), "\n", 2)[0])
	}
	if !strings.Contains(rr.Body.String(), "中国") {
		t.Fatalf("export row missing country: %q", rr.Body.String())
	}

	// The analysis snapshot labels the same source IP for the console and the
	// assistant's grounding text.
	snap, err := analyze.Build(s.Store, s.geoLookup)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.IPs) != 1 || snap.IPs[0].Country != "中国" || snap.IPs[0].Org != "CHINANET-BACKBONE" {
		t.Fatalf("snapshot ips = %+v", snap.IPs)
	}
	if txt := snap.Text(); !strings.Contains(txt, "来源地区：中国(1)") {
		t.Fatalf("snapshot text missing region summary: %q", txt)
	}
}
