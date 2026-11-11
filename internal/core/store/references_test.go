package store

import (
	"path/filepath"
	"testing"
)

func TestCampaignReferenceChecks(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ref.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tid, _ := st.UpsertTemplate(EmailTemplate{Name: "模板A", Subject: "s", HTML: "<p>x</p>"})
	pid, _ := st.UpsertPage(LandingPage{Name: "页面A", Kind: "template", Body: "<form></form>"}, nil)
	gid, _ := st.CreateGroup("群组A")
	_, _ = st.AddTargetsToGroup(gid, []Target{{Email: "a@example.com"}})
	profID, _ := st.UpsertSendingProfile(SendingProfile{Name: "账号A", Host: "smtp.example.com", Port: 587, Username: "u@example.com"})
	_, err = st.CreateCampaign(Campaign{
		Name: "活动A", EmailTemplateID: tid, LandingPageID: pid, SendingProfileID: profID,
	}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	for name, fn := range map[string]func() ([]string, error){
		"template": func() ([]string, error) { return st.CampaignsUsingTemplate(tid) },
		"page":     func() ([]string, error) { return st.CampaignsUsingPage(pid) },
		"profile":  func() ([]string, error) { return st.CampaignsUsingProfile(profID) },
		"group":    func() ([]string, error) { return st.CampaignsUsingGroup(gid) },
	} {
		names, err := fn()
		if err != nil || len(names) != 1 || names[0] != "活动A" {
			t.Fatalf("%s references = %+v err=%v", name, names, err)
		}
	}
}

func TestReferenceChecksIncludeRecycleBin(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ref2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tid, _ := st.UpsertTemplate(EmailTemplate{Name: "模板B", Subject: "s", HTML: "<p>x</p>"})
	pid, _ := st.UpsertPage(LandingPage{Name: "页面B", Kind: "template", Body: "<form></form>"}, nil)
	gid, _ := st.CreateGroup("群组B")
	cid, _ := st.CreateCampaign(Campaign{Name: "活动B", EmailTemplateID: tid, LandingPageID: pid}, []int64{gid})
	if err := st.SoftDeleteCampaign(cid); err != nil {
		t.Fatal(err)
	}
	if names, _ := st.CampaignsUsingTemplate(tid); len(names) != 1 || names[0] != "活动B" {
		t.Fatalf("template refs = %+v", names)
	}
	if names, _ := st.CampaignsUsingPage(pid); len(names) != 1 {
		t.Fatalf("page refs = %+v", names)
	}
	if names, _ := st.CampaignsUsingGroup(gid); len(names) != 1 {
		t.Fatalf("group refs = %+v", names)
	}
}
