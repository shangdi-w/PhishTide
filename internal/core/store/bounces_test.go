package store

import (
	"path/filepath"
	"strings"
	"testing"
)

// bounceFixture builds a campaign with one sent result and returns its ids.
func bounceFixture(t *testing.T, s *Store, email string) (campaignID, resultID int64) {
	t.Helper()
	tpl, err := s.UpsertTemplate(EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.UpsertPage(LandingPage{Name: "p", Kind: "template", Body: "<p>x</p>"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := s.CreateGroup("g")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddTargetsToGroup(gid, []Target{{Email: email}}); err != nil {
		t.Fatal(err)
	}
	cid, err := s.CreateCampaign(Campaign{Name: "c", EmailTemplateID: tpl, LandingPageID: page}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	results, err := s.ListResults(cid)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d", len(results))
	}
	s.MarkSent(results[0].ID)
	return cid, results[0].ID
}

func TestBouncesRecordReplaceAndCount(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "bounces.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cid, rid := bounceFixture(t, s, "Victim@Example.com")

	if err := s.RecordBounce(Bounce{
		CampaignID: cid, ResultID: rid, Email: "victim@example.com",
		Kind: "soft", Action: "delayed", Status: "4.4.1", Diagnostic: "connection timed out",
	}); err != nil {
		t.Fatal(err)
	}
	// A final hard verdict replaces the earlier delay for the same recipient.
	if err := s.RecordBounce(Bounce{
		CampaignID: cid, ResultID: rid, Email: "victim@example.com",
		Kind: "hard", Action: "failed", Status: "5.1.1", Diagnostic: strings.Repeat("x", 2000),
	}); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListBounces(cid, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Kind != "hard" || list[0].Status != "5.1.1" {
		t.Fatalf("list = %+v", list)
	}
	if len(list[0].Diagnostic) > bounceMaxDiagnostic {
		t.Fatalf("diagnostic not truncated: %d", len(list[0].Diagnostic))
	}
	counts, err := s.CountBouncesByKind(cid)
	if err != nil || counts["hard"] != 1 || counts["soft"] != 0 {
		t.Fatalf("counts = %+v err=%v", counts, err)
	}

	// Unmatched notices (campaign 0) stay visible in the global list.
	if err := s.RecordBounce(Bounce{Email: "stranger@example.com", Kind: "hard", Status: "5.1.1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordBounce(Bounce{Email: "stranger@example.com", Kind: "hard", Status: "5.1.1"}); err != nil {
		t.Fatal(err)
	}
	all, err := s.ListAllBounces(0)
	if err != nil || len(all) != 3 {
		t.Fatalf("all = %+v err=%v", all, err)
	}
}

func TestBounceFindResultAndMark(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "find.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cid, rid := bounceFixture(t, s, "Victim@Example.com")

	r, err := s.FindResultByEmail("  victim@EXAMPLE.com ")
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != rid || r.CampaignID != cid {
		t.Fatalf("found = %+v", r)
	}
	if _, err := s.FindResultByEmail("nobody@example.com"); err == nil {
		t.Fatal("expected no match for unknown address")
	}

	s.MarkBounced(rid, "hard")
	results, _ := s.ListResults(cid)
	if results[0].Status != "bounced" {
		t.Fatalf("status = %q", results[0].Status)
	}
	s.MarkBounced(rid, "soft")
	results, _ = s.ListResults(cid)
	if results[0].Status != "delayed" {
		t.Fatalf("soft status = %q", results[0].Status)
	}
}

func TestBouncesDeletedWithCampaign(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "cascade.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cid, rid := bounceFixture(t, s, "victim@example.com")
	if err := s.RecordBounce(Bounce{CampaignID: cid, ResultID: rid, Email: "victim@example.com", Kind: "hard"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteCampaign(cid); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListBounces(cid, 0)
	if err != nil || len(list) != 0 {
		t.Fatalf("after delete = %+v err=%v", list, err)
	}
}
