package web

import (
	"path/filepath"
	"strings"
	"testing"

	"phishsim/internal/core/config"
	"phishsim/internal/core/store"
)

func TestSendGuards(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "send.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SetSecretKey(make([]byte, 32))

	tid, err := st.UpsertTemplate(store.EmailTemplate{
		Name: "t", Subject: "hello", HTML: "<p>{{.Email}}</p>", Text: "hello",
	})
	if err != nil {
		t.Fatal(err)
	}
	pid, err := st.UpsertPage(store.LandingPage{
		Name: "p", Kind: "template", Body: "<p>x</p>", CaptureCredentials: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := st.CreateGroup("g")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddTargetsToGroup(gid, []store.Target{
		{Email: "a@example.com"}, {Email: "b@example.com"}, {Email: "c@example.com"},
	}); err != nil {
		t.Fatal(err)
	}
	profID, err := st.UpsertSendingProfile(store.SendingProfile{
		Name: "p", InterfaceType: "SMTP", Host: "smtp.example.com", Port: 587,
		TLSMode: "starttls", FromEmail: "it@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	campID, err := st.CreateCampaign(store.Campaign{
		Name: "c", EmailTemplateID: tid, LandingPageID: pid, SendingProfileID: profID,
	}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{Cfg: &config.Config{
		PublicURL:      "https://phish.example.com",
		MaxSendTargets: 2,
	}, Store: st}

	// A real send above the cap must be refused before any SMTP traffic.
	if _, err := s.sendCampaignEmail(campID, 0, 0, false); err == nil || !strings.Contains(err.Error(), "超过单次上限") {
		t.Fatalf("over-limit send was not refused: %v", err)
	}

	// A dry run ignores the cap, renders previews and never marks anything sent.
	out, err := s.sendCampaignEmail(campID, 0, 0, true)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !out.DryRun || out.Sent != 0 || len(out.Previews) == 0 {
		t.Fatalf("unexpected dry-run outcome: %+v", out)
	}
	results, err := st.ListResults(campID)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Sent {
			t.Fatal("dry run marked a result as sent")
		}
	}
}
