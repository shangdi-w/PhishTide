package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"phishsim/internal/core/store"
)

func TestAdminSendHistoryReturnsLedger(t *testing.T) {
	s := newAgentServer(t)
	_ = s.Store.RecordSendLedger(store.SendLedgerEntry{
		CampaignID: 7, CampaignName: "演练A", Email: "alice@example.com",
		Subject: "密码过期", Status: "sent", Variant: "A",
	})
	rr := httptest.NewRecorder()
	s.adminSendHistory(rr, httptest.NewRequest(http.MethodGet, "/__admin/api/send-history?query=alice", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		Entries []store.SendLedgerEntry `json:"entries"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 1 || out.Entries[0].CampaignName != "演练A" {
		t.Fatalf("entries = %+v", out.Entries)
	}
}

func TestSendHistoryToolSeesLedger(t *testing.T) {
	s := newAgentServer(t)
	_ = s.Store.RecordSendLedger(store.SendLedgerEntry{
		CampaignID: 3, CampaignName: "已删除活动", Email: "victim@example.com",
		Subject: "通知", Status: "sent",
	})
	out, ok, _ := s.executeTool(context.Background(), 0, toolCall(t, "send_history", map[string]any{"query": "victim"}), func(any) error { return nil })
	if !ok {
		t.Fatalf("send_history failed: %s", out)
	}
	var res map[string]any
	_ = json.Unmarshal([]byte(out), &res)
	if res["count"].(float64) != 1 || res["sent"].(float64) != 1 {
		t.Fatalf("send_history result = %+v", res)
	}
	if !strings.Contains(out, "已删除活动") {
		t.Fatalf("ledger entry missing: %s", out)
	}
}

func TestSearchChatHistoryTool(t *testing.T) {
	s := newAgentServer(t)
	sid, _ := s.Store.CreateChatSession("发送记录会话")
	_, _ = s.Store.AppendChatMessage(sid, "assistant", "✅ 已发送活动「Token空投」：成功 1，失败 0", "")
	out, ok, _ := s.executeTool(context.Background(), 0, toolCall(t, "search_chat_history", map[string]any{"query": "已发送活动"}), func(any) error { return nil })
	if !ok || !strings.Contains(out, "Token空投") {
		t.Fatalf("search_chat_history = %s ok=%v", out, ok)
	}
}

func TestSendHistoryToolIncludesLiveCampaigns(t *testing.T) {
	s := newAgentServer(t)
	tid, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	pid, _ := s.Store.UpsertPage(store.LandingPage{Name: "p", Kind: "template", Body: "<form></form>"}, nil)
	gid, _ := s.Store.CreateGroup("g")
	_, _ = s.Store.AddTargetsToGroup(gid, []store.Target{{Email: "a@example.com"}})
	cid, _ := s.Store.CreateCampaign(store.Campaign{Name: "Token空投领取演练-v2", EmailTemplateID: tid, LandingPageID: pid}, []int64{gid})
	results, _ := s.Store.ListResults(cid)
	if len(results) == 1 {
		s.Store.MarkSent(results[0].ID)
	}
	out, ok, _ := s.executeTool(context.Background(), 0, toolCall(t, "send_history", map[string]any{"query": "Token空投"}), func(any) error { return nil })
	if !ok {
		t.Fatalf("send_history failed: %s", out)
	}
	var res struct {
		Live []struct {
			Name string `json:"name"`
			Sent int    `json:"sent"`
		} `json:"live_campaigns"`
	}
	_ = json.Unmarshal([]byte(out), &res)
	if len(res.Live) != 1 || res.Live[0].Sent != 1 {
		t.Fatalf("live campaign evidence missing: %s", out)
	}
}

func TestSendStatusVerdicts(t *testing.T) {
	s := newAgentServer(t)

	// No evidence → unknown.
	out, ok, _ := s.executeTool(context.Background(), 0, toolCall(t, "send_status", map[string]any{"campaign_name": "不存在"}), func(any) error { return nil })
	if !ok {
		t.Fatalf("send_status failed: %s", out)
	}
	var res map[string]any
	_ = json.Unmarshal([]byte(out), &res)
	if res["verdict"] != "unknown" {
		t.Fatalf("empty verdict = %v", res["verdict"])
	}

	// Ledger evidence → sent.
	_ = s.Store.RecordSendLedger(store.SendLedgerEntry{
		CampaignID: 9, CampaignName: "台账活动", Email: "alice@example.com",
		Subject: "通知", Status: "sent", MessageID: "<abc@example.com>",
	})
	out, _, _ = s.executeTool(context.Background(), 0, toolCall(t, "send_status", map[string]any{"email": "alice@example.com"}), func(any) error { return nil })
	_ = json.Unmarshal([]byte(out), &res)
	if res["verdict"] != "sent" || res["sent_count"].(float64) != 1 {
		t.Fatalf("ledger verdict = %+v", res)
	}
	if !strings.Contains(out, "abc@example.com") {
		t.Fatalf("message id missing from evidence: %s", out)
	}

	// Live campaign evidence → sent.
	tid, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	pid, _ := s.Store.UpsertPage(store.LandingPage{Name: "p", Kind: "template", Body: "<form></form>"}, nil)
	gid, _ := s.Store.CreateGroup("g")
	_, _ = s.Store.AddTargetsToGroup(gid, []store.Target{{Email: "b@example.com"}})
	cid, _ := s.Store.CreateCampaign(store.Campaign{Name: "现存活动", EmailTemplateID: tid, LandingPageID: pid}, []int64{gid})
	results, _ := s.Store.ListResults(cid)
	if len(results) == 1 {
		s.Store.MarkSent(results[0].ID)
	}
	out, _, _ = s.executeTool(context.Background(), 0, toolCall(t, "send_status", map[string]any{"campaign_name": "现存活动"}), func(any) error { return nil })
	_ = json.Unmarshal([]byte(out), &res)
	if res["verdict"] != "sent" || res["live_sent"].(float64) != 1 {
		t.Fatalf("live verdict = %+v", res)
	}

	// Chat receipt only → sent.
	sid, _ := s.Store.CreateChatSession("回执会话")
	_, _ = s.Store.AppendChatMessage(sid, "assistant", "✅ 已发送活动「回执活动」：成功 2，失败 0", "")
	out, _, _ = s.executeTool(context.Background(), 0, toolCall(t, "send_status", map[string]any{"campaign_name": "回执活动"}), func(any) error { return nil })
	_ = json.Unmarshal([]byte(out), &res)
	if res["verdict"] != "sent" || res["receipt_sent"].(float64) != 2 {
		t.Fatalf("receipt verdict = %+v", res)
	}
}

func TestChatPendingListsWithoutConsuming(t *testing.T) {
	s := newAgentServer(t)
	sid, _ := s.Store.CreateChatSession("")
	act := s.issueAction(sid, "create_group", `{"name":"g"}`, "agent_action", "create_group", "创建组")
	conf := s.issueConfirm(sid, store.Campaign{ID: 1, Name: "活动"}, store.SendingProfile{FromEmail: "a@example.com"}, store.EmailTemplate{Subject: "s"}, 2)

	rr := httptest.NewRecorder()
	s.adminChatPending(rr, httptest.NewRequest(http.MethodGet, "/__admin/api/chat/pending?session_id="+itoa64(sid), nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d", rr.Code)
	}
	var out struct {
		Actions  []pendingAction  `json:"actions"`
		Confirms []pendingConfirm `json:"confirms"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Actions) != 1 || out.Actions[0].ID != act.ID || len(out.Confirms) != 1 || out.Confirms[0].ID != conf.ID {
		t.Fatalf("pending = %+v", out)
	}
	// Listing must not consume: the confirm endpoint can still take it.
	if p, ok := s.takeAction(act.ID, sid); !ok || p.ID != act.ID {
		t.Fatal("pending listing consumed the action")
	}
}

func TestScheduleInterpretsBeijingTime(t *testing.T) {
	s := newAgentServer(t)
	tid, _ := s.Store.UpsertTemplate(store.EmailTemplate{Name: "t", Subject: "s", HTML: "<p>x</p>"})
	pid, _ := s.Store.UpsertPage(store.LandingPage{Name: "p", Kind: "template", Body: "<form></form>"}, nil)
	gid, _ := s.Store.CreateGroup("g")
	cid, err := s.Store.CreateCampaign(store.Campaign{Name: "c", EmailTemplateID: tid, LandingPageID: pid}, []int64{gid})
	if err != nil {
		t.Fatal(err)
	}

	body := bytes.NewBufferString(`{"scheduled_at":"2099-01-01T20:00:00+08:00"}`)
	rr := httptest.NewRecorder()
	s.adminScheduleSend(rr, httptest.NewRequest(http.MethodPost, "/__admin/api/campaigns/1/schedule", body), cid)
	if rr.Code != 200 {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	at, _ := out["scheduled_at"].(string)
	if !strings.HasPrefix(at, "2099-01-01T12:00:00") || !strings.HasSuffix(at, "Z") {
		t.Fatalf("scheduled_at = %q (want UTC 12:00Z for Beijing 20:00)", at)
	}

	// Naive wall-clock strings are also interpreted as Beijing time.
	body = bytes.NewBufferString(`{"scheduled_at":"2099-01-02T08:30:00"}`)
	rr = httptest.NewRecorder()
	s.adminScheduleSend(rr, httptest.NewRequest(http.MethodPost, "/__admin/api/campaigns/1/schedule", body), cid)
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if at, _ := out["scheduled_at"].(string); !strings.HasPrefix(at, "2099-01-02T00:30:00") {
		t.Fatalf("naive scheduled_at = %q", at)
	}

	// Garbage is rejected rather than silently sent now.
	body = bytes.NewBufferString(`{"scheduled_at":"tomorrow"}`)
	rr = httptest.NewRecorder()
	s.adminScheduleSend(rr, httptest.NewRequest(http.MethodPost, "/__admin/api/campaigns/1/schedule", body), cid)
	if rr.Code != 400 {
		t.Fatalf("bad time accepted: %d %s", rr.Code, rr.Body.String())
	}
}
