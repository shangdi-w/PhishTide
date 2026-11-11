package web

// sendStatus answers "was this actually sent?" in one deterministic call.
// Unlike send_history (a raw ledger), this merges every durable source and
// returns a verdict plus the evidence behind it, so the model only has to
// repeat a conclusion instead of reasoning over partial data.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var receiptSentRe = regexp.MustCompile(`已发送活动.*?成功\s*(\d+)`)

type sendEvidence struct {
	Source  string `json:"source"`
	Detail  string `json:"detail"`
	At      string `json:"at,omitempty"`
	Success int    `json:"success,omitempty"`
}

func (s *Server) sendStatus(campaignID int64, campaignName, email string) (map[string]any, error) {
	name := strings.ToLower(strings.TrimSpace(campaignName))
	mail := strings.ToLower(strings.TrimSpace(email))
	query := strings.TrimSpace(campaignName)
	if query == "" {
		query = strings.TrimSpace(email)
	}

	ledger, err := s.Store.ListSendLedger(100, query, campaignID)
	if err != nil {
		return nil, err
	}
	evidence := []sendEvidence{}
	ledgerSent, ledgerFailed := 0, 0
	firstSent := ""
	for _, e := range ledger {
		if mail != "" && !strings.EqualFold(e.Email, email) {
			continue
		}
		mid := ""
		if e.MessageID != "" {
			mid = "（Message-ID " + e.MessageID + "）"
		}
		if e.Status == "sent" {
			ledgerSent++
			if firstSent == "" {
				firstSent = e.CreatedAt
			}
			evidence = append(evidence, sendEvidence{
				Source: "send_ledger", At: e.CreatedAt,
				Detail: fmt.Sprintf("台账：%s → %s，%s%s", e.CampaignName, e.Email, e.Subject, mid),
			})
		} else {
			ledgerFailed++
			evidence = append(evidence, sendEvidence{
				Source: "send_ledger", At: e.CreatedAt,
				Detail: fmt.Sprintf("台账失败：%s → %s，%s（%s）%s", e.CampaignName, e.Email, e.Subject, e.FailureKind, mid),
			})
		}
	}

	liveSent, liveFailed := 0, false
	if camps, cerr := s.Store.ListCampaigns(); cerr == nil {
		for _, c := range camps {
			if campaignID > 0 && c.ID != campaignID {
				continue
			}
			if campaignID <= 0 && name != "" && !strings.Contains(strings.ToLower(c.Name), name) {
				continue
			}
			if campaignID <= 0 && name == "" {
				continue
			}
			if c.Sent > 0 {
				liveSent += c.Sent
				evidence = append(evidence, sendEvidence{
					Source: "campaign", Success: c.Sent,
					Detail: fmt.Sprintf("活动「%s」：目标 %d，已发 %d，打开 %d，点击 %d，提交 %d", c.Name, c.Targets, c.Sent, c.Opened, c.Clicked, c.Submitted),
				})
			} else if c.Targets > 0 {
				liveFailed = true
				evidence = append(evidence, sendEvidence{
					Source: "campaign",
					Detail: fmt.Sprintf("活动「%s」：目标 %d，已发 0（可能未发送或发送失败）", c.Name, c.Targets),
				})
			}
		}
	}

	deletedSent := 0
	if deleted, derr := s.Store.ListDeletedCampaigns(50); derr == nil {
		for _, c := range deleted {
			if campaignID > 0 && c.CampaignID != campaignID {
				continue
			}
			if name != "" && !strings.Contains(strings.ToLower(c.Name), name) {
				continue
			}
			deletedSent += c.Sent
			evidence = append(evidence, sendEvidence{
				Source: "deleted_campaign", At: c.DeletedAt, Success: c.Sent,
				Detail: fmt.Sprintf("已删除活动「%s」：删除前已发 %d / 目标 %d", c.Name, c.Sent, c.Targets),
			})
		}
	}

	receiptSent := 0
	receiptQuery := strings.TrimSpace(campaignName)
	if receiptQuery == "" {
		receiptQuery = "已发送活动"
	}
	if hits, herr := s.Store.SearchChatMessages(receiptQuery, 20); herr == nil {
		for _, h := range hits {
			if !strings.Contains(h.Content, "已发送活动") {
				continue
			}
			if name != "" && !strings.Contains(strings.ToLower(h.Content), name) {
				continue
			}
			m := receiptSentRe.FindStringSubmatch(h.Content)
			if len(m) < 2 {
				continue
			}
			n, _ := strconv.Atoi(m[1])
			if n > receiptSent {
				receiptSent = n
			}
			evidence = append(evidence, sendEvidence{
				Source: "chat_receipt", At: h.CreatedAt, Success: n,
				Detail: "历史会话回执：" + truncateRunes(h.Content, 180),
			})
		}
	}

	verdict := "unknown"
	sentCount := maxInt(ledgerSent, maxInt(liveSent, maxInt(deletedSent, receiptSent)))
	switch {
	case sentCount > 0:
		verdict = "sent"
	case ledgerFailed > 0 && liveSent == 0:
		verdict = "failed"
	case liveFailed && ledgerSent == 0:
		verdict = "unknown"
	}
	return map[string]any{
		"verdict":       verdict,
		"sent_count":    sentCount,
		"failed_count":  ledgerFailed,
		"first_sent_at": firstSent,
		"ledger_sent":   ledgerSent,
		"live_sent":     liveSent,
		"deleted_sent":  deletedSent,
		"receipt_sent":  receiptSent,
		"evidence":      evidence,
	}, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
