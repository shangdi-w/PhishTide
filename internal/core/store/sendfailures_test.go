package store

import (
	"path/filepath"
	"testing"
)

func TestSendFailuresRecordReplaceClear(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "fail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.RecordSendFailure(SendFailure{
		CampaignID: 7, ResultID: 11, Email: "a@example.com",
		Kind: "soft", Error: "451 try again later", Attempts: 3,
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListSendFailures(7, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Kind != "soft" || rows[0].Attempts != 3 {
		t.Fatalf("after record: %+v", rows)
	}

	// A later failure for the same recipient replaces the previous reason.
	if err := s.RecordSendFailure(SendFailure{
		CampaignID: 7, ResultID: 11, Email: "a@example.com",
		Kind: "hard", Error: "550 no such user", Attempts: 1,
	}); err != nil {
		t.Fatal(err)
	}
	rows, _ = s.ListSendFailures(7, 0)
	if len(rows) != 1 || rows[0].Kind != "hard" {
		t.Fatalf("after replace: %+v", rows)
	}

	// Seed rows (result_id 0) are stored independently and do not replace.
	if err := s.RecordSendFailure(SendFailure{
		CampaignID: 7, ResultID: 0, Email: "seed@example.com",
		Kind: "dns", Error: "no such host", Attempts: 1,
	}); err != nil {
		t.Fatal(err)
	}
	rows, _ = s.ListSendFailures(7, 0)
	if len(rows) != 2 {
		t.Fatalf("after seed: %+v", rows)
	}

	// Success clears only that recipient's row.
	if err := s.ClearSendFailure(7, 11); err != nil {
		t.Fatal(err)
	}
	rows, _ = s.ListSendFailures(7, 0)
	if len(rows) != 1 || rows[0].Email != "seed@example.com" {
		t.Fatalf("after clear: %+v", rows)
	}

	// Deleting a campaign removes its failure rows.
	tid, _ := s.UpsertTemplate(EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	pid, _ := s.UpsertPage(LandingPage{Name: "p", Kind: "template", Body: "<p>x</p>"}, nil)
	gid, _ := s.CreateGroup("g")
	cid, err := s.CreateCampaign(Campaign{Name: "c", EmailTemplateID: tid, LandingPageID: pid}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RecordSendFailure(SendFailure{CampaignID: cid, ResultID: 12, Email: "b@example.com", Kind: "auth"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteCampaign(cid); err != nil {
		t.Fatal(err)
	}
	rows, _ = s.ListSendFailures(cid, 0)
	if len(rows) != 0 {
		t.Fatalf("rows for deleted campaign: %+v", rows)
	}
}

func TestSendFailureErrorTruncated(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "failtrim.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	long := make([]byte, sendFailureMaxText+200)
	for i := range long {
		long[i] = 'x'
	}
	if err := s.RecordSendFailure(SendFailure{CampaignID: 1, ResultID: 2, Email: "a@b", Kind: "unknown", Error: string(long)}); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.ListSendFailures(1, 0)
	if len(rows) != 1 || len(rows[0].Error) != sendFailureMaxText {
		t.Fatalf("error length = %d", len(rows[0].Error))
	}
}
