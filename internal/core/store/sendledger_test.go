package store

import (
	"path/filepath"
	"testing"
)

func TestSearchChatMessagesOnlyAssistant(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sid, _ := st.CreateChatSession("会话A")
	_, _ = st.AppendChatMessage(sid, "user", "我的密码是 secret123", "")
	_, _ = st.AppendChatMessage(sid, "assistant", "✅ 已发送活动「Token空投」：成功 1，失败 0", "")

	hits, err := st.SearchChatMessages("已发送活动", 10)
	if err != nil || len(hits) != 1 {
		t.Fatalf("hits = %+v err=%v", hits, err)
	}
	if hits[0].Role != "assistant" || hits[0].Title != "会话A" {
		t.Fatalf("hit = %+v", hits[0])
	}
	// User input is never searched (may contain credentials).
	if res, _ := st.SearchChatMessages("secret123", 10); len(res) != 0 {
		t.Fatalf("user messages must not match: %+v", res)
	}
}

func TestSendLedgerRecordsAndFilters(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "sl.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.RecordSendLedger(SendLedgerEntry{
		CampaignID: 1, CampaignName: "活动A", TemplateID: 9,
		Email: "alice@example.com", Subject: "密码过期", FromEmail: "it@example.com",
		Variant: "A", Status: "sent",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordSendLedger(SendLedgerEntry{
		CampaignID: 2, CampaignName: "活动B", TemplateID: 9,
		Email: "bob@example.com", Subject: "工资条", Status: "failed", FailureKind: "auth",
		Detail: "535 auth failed",
	}); err != nil {
		t.Fatal(err)
	}

	all, err := st.ListSendLedger(10, "", 0)
	if err != nil || len(all) != 2 {
		t.Fatalf("all = %+v err=%v", all, err)
	}
	byCamp, _ := st.ListSendLedger(10, "", 1)
	if len(byCamp) != 1 || byCamp[0].Email != "alice@example.com" {
		t.Fatalf("by campaign = %+v", byCamp)
	}
	byQuery, _ := st.ListSendLedger(10, "ALICE", 0)
	if len(byQuery) != 1 {
		t.Fatalf("query filter = %+v", byQuery)
	}
	bySubject, _ := st.ListSendLedger(10, "工资", 0)
	if len(bySubject) != 1 || bySubject[0].FailureKind != "auth" {
		t.Fatalf("subject filter = %+v", bySubject)
	}

	// The ledger is independent of campaign deletion.
	if err := st.RecordDeletedCampaign(DeletedCampaign{CampaignID: 1, Name: "活动A", Targets: 5, Sent: 5}); err != nil {
		t.Fatal(err)
	}
	deleted, _ := st.ListDeletedCampaigns(10)
	if len(deleted) != 1 || deleted[0].Sent != 5 {
		t.Fatalf("deleted campaigns = %+v", deleted)
	}
	if again, _ := st.ListSendLedger(10, "", 1); len(again) != 1 {
		t.Fatalf("ledger vanished after tombstone: %+v", again)
	}
}
