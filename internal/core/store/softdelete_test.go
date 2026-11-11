package store

import (
	"path/filepath"
	"testing"
)

func TestSoftDeleteCampaignPreservesData(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "sd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tid, _ := st.UpsertTemplate(EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	pid, _ := st.UpsertPage(LandingPage{Name: "p", Kind: "template", Body: "<form></form>"}, nil)
	gid, _ := st.CreateGroup("g")
	_, _ = st.AddTargetsToGroup(gid, []Target{{Email: "a@example.com"}})
	cid, err := st.CreateCampaign(Campaign{Name: "软删除活动", EmailTemplateID: tid, LandingPageID: pid}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}
	results, _ := st.ListResults(cid)
	if len(results) != 1 {
		t.Fatalf("results = %+v", results)
	}
	st.MarkSent(results[0].ID)

	if err := st.SoftDeleteCampaign(cid); err != nil {
		t.Fatal(err)
	}
	list, _ := st.ListCampaigns()
	for _, c := range list {
		if c.ID == cid {
			t.Fatal("soft-deleted campaign still in the active list")
		}
	}
	camp, err := st.GetCampaign(cid)
	if err != nil || camp.DeletedAt == "" || camp.Sent != 1 {
		t.Fatalf("deleted campaign = %+v err=%v", camp, err)
	}
	deleted, _ := st.ListCampaignsInRecycleBin()
	if len(deleted) != 1 || deleted[0].ID != cid || deleted[0].Sent != 1 {
		t.Fatalf("recycle bin = %+v", deleted)
	}
	// Results and counters survive the soft delete.
	if again, _ := st.ListResults(cid); len(again) != 1 || !again[0].Sent {
		t.Fatalf("results lost after soft delete: %+v", again)
	}
	if err := st.SoftDeleteCampaign(cid); err == nil {
		t.Fatal("double soft delete should fail")
	}

	if err := st.RestoreCampaign(cid); err != nil {
		t.Fatal(err)
	}
	list, _ = st.ListCampaigns()
	found := false
	for _, c := range list {
		if c.ID == cid {
			found = true
		}
	}
	if !found {
		t.Fatal("restored campaign not in the active list")
	}
	if again, _ := st.ListResults(cid); len(again) != 1 {
		t.Fatalf("results lost after restore: %+v", again)
	}
}
