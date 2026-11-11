package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAddCampaignTargetsCreatesResultsAndSkipsDuplicates(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ct.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tid, _ := st.UpsertTemplate(EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	pid, _ := st.UpsertPage(LandingPage{Name: "p", Kind: "template", Body: "<form></form>"}, nil)
	gid, _ := st.CreateGroup("原名单")
	_, _ = st.AddTargetsToGroup(gid, []Target{{Email: "a@example.com"}})
	campID, err := st.CreateCampaign(Campaign{Name: "c", EmailTemplateID: tid, LandingPageID: pid}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}

	added, skipped, err := st.AddCampaignTargets(campID, []Target{
		{Email: "A@EXAMPLE.COM"}, // duplicate of a@example.com (case-insensitive)
		{Email: "b@example.com", Department: "财务部"},
		{Email: "not-an-email"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 || skipped != 2 {
		t.Fatalf("added=%d skipped=%d", added, skipped)
	}

	results, err := st.ListResults(campID)
	if err != nil || len(results) != 2 {
		t.Fatalf("results = %+v err=%v", results, err)
	}
	var found bool
	for _, r := range results {
		if r.Email == "b@example.com" {
			found = true
			if r.Rid == "" {
				t.Fatal("new target missing rid")
			}
			if r.Department != "财务部" {
				t.Fatalf("department = %q", r.Department)
			}
		}
	}
	if !found {
		t.Fatalf("new target missing from results: %+v", results)
	}
	camp, _ := st.GetCampaign(campID)
	if camp.Targets != 2 {
		t.Fatalf("campaign targets = %d", camp.Targets)
	}
	groups, _ := st.ListGroups()
	var direct *Group
	for i := range groups {
		if strings.Contains(groups[i].Name, "追加目标") {
			direct = &groups[i]
		}
	}
	if direct == nil || direct.TargetCount != 1 {
		t.Fatalf("direct group missing or wrong count: %+v", groups)
	}
}
