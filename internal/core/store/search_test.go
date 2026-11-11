package store

import (
	"path/filepath"
	"testing"
)

func TestGlobalSearchAcrossResources(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "gs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sid, _ := st.CreateChatSession("会话甲")
	_, _ = st.AppendChatMessage(sid, "user", "帮我找 needle 模板", "")
	tid, _ := st.UpsertTemplate(EmailTemplate{Name: "needle模板", Subject: "needle主题", HTML: "<p>needle</p>"})
	pid, _ := st.UpsertPage(LandingPage{Name: "needle页面", Kind: "template", Body: "<p>needle</p>"}, nil)
	gid, _ := st.CreateGroup("g")
	cid, _ := st.CreateCampaign(Campaign{Name: "needle活动", EmailTemplateID: tid, LandingPageID: pid}, []int64{gid})
	_ = st.RecordSendLedger(SendLedgerEntry{CampaignID: cid, CampaignName: "needle活动", Email: "needle@example.com", Subject: "needle主题", Status: "sent"})

	hits, err := st.GlobalSearch("needle", 5)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, h := range hits {
		kinds[h.Kind] = true
	}
	for _, want := range []string{"session", "template", "page", "campaign", "ledger"} {
		if !kinds[want] {
			t.Fatalf("missing kind %s in %+v", want, hits)
		}
	}
}

func TestSendLedgerPageOffset(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "pg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for i := 0; i < 3; i++ {
		_ = st.RecordSendLedger(SendLedgerEntry{CampaignName: "c", Email: "a@example.com", Subject: "s", Status: "sent"})
	}
	p1, _ := st.ListSendLedgerPage(2, 0, "", 0)
	p2, _ := st.ListSendLedgerPage(2, 2, "", 0)
	if len(p1) != 2 || len(p2) != 1 {
		t.Fatalf("pages = %d,%d", len(p1), len(p2))
	}
}
