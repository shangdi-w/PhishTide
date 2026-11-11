package store

import (
	"path/filepath"
	"testing"
)

func TestDeleteSubmissions(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "sub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tid, _ := st.UpsertTemplate(EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	pid, _ := st.UpsertPage(LandingPage{Name: "p", Kind: "template", Body: "<form></form>"}, nil)
	gid, _ := st.CreateGroup("g")
	_, _ = st.AddTargetsToGroup(gid, []Target{{Email: "a@example.com"}})
	cid, _ := st.CreateCampaign(Campaign{Name: "c", EmailTemplateID: tid, LandingPageID: pid}, []int64{gid})
	results, _ := st.ListResults(cid)
	if len(results) != 1 {
		t.Fatalf("results = %+v", results)
	}
	if err := st.RecordSubmission(results[0], "127.0.0.1", "ua", "", "u", "p", map[string][]string{"email": {"a@example.com"}}); err != nil {
		t.Fatal(err)
	}
	subs, _ := st.ListSubmissions(cid)
	if len(subs) != 1 {
		t.Fatalf("submissions = %+v", subs)
	}
	// Wrong campaign must not delete.
	if n, _ := st.DeleteSubmissions(cid+1, []int64{subs[0].ID}); n != 0 {
		t.Fatalf("wrong campaign deleted %d", n)
	}
	if n, _ := st.DeleteSubmissions(cid, []int64{subs[0].ID}); n != 1 {
		t.Fatalf("deleted %d", n)
	}
	if subs, _ := st.ListSubmissions(cid); len(subs) != 0 {
		t.Fatalf("left = %+v", subs)
	}
}
