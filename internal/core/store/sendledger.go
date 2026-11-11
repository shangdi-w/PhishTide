package store

// Durable send ledger and deletion tombstones. Campaign rows (and their
// results/submissions) are deletable; the ledger is not, so the platform can
// still answer "was this actually sent" after the campaign is gone.

import (
	"strings"
)

// SendLedgerEntry is one delivered or failed recipient attempt.
type SendLedgerEntry struct {
	ID           int64  `json:"id"`
	CampaignID   int64  `json:"campaign_id"`
	CampaignName string `json:"campaign_name"`
	TemplateID   int64  `json:"template_id"`
	Email        string `json:"email"`
	Subject      string `json:"subject"`
	FromEmail    string `json:"from_email"`
	Variant      string `json:"variant"`
	Status       string `json:"status"` // sent | failed
	FailureKind  string `json:"failure_kind"`
	Detail       string `json:"detail"`
	MessageID    string `json:"message_id"`
	CreatedAt    string `json:"created_at"`
}

// DeletedCampaign records a campaign that was removed after being created.
type DeletedCampaign struct {
	ID         int64  `json:"id"`
	CampaignID int64  `json:"campaign_id"`
	Name       string `json:"name"`
	Targets    int    `json:"targets"`
	Sent       int    `json:"sent"`
	DeletedAt  string `json:"deleted_at"`
}

func (s *Store) RecordSendLedger(e SendLedgerEntry) error {
	_, err := s.db.Exec(
		`INSERT INTO send_ledger(campaign_id, campaign_name, template_id, email, subject, from_email, variant, status, failure_kind, detail, message_id, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.CampaignID, e.CampaignName, e.TemplateID, e.Email, e.Subject, e.FromEmail,
		e.Variant, e.Status, e.FailureKind, truncateStr(e.Detail, 800), e.MessageID, now(),
	)
	return err
}

// ListSendLedger returns the first page of ledger entries.
func (s *Store) ListSendLedger(limit int, query string, campaignID int64) ([]SendLedgerEntry, error) {
	return s.ListSendLedgerPage(limit, 0, query, campaignID)
}

// ListSendLedgerPage returns ledger entries newest first with offset paging.
func (s *Store) ListSendLedgerPage(limit, offset int, query string, campaignID int64) ([]SendLedgerEntry, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	where := []string{}
	args := []any{}
	if campaignID > 0 {
		where = append(where, "campaign_id = ?")
		args = append(args, campaignID)
	}
	if q := strings.TrimSpace(strings.ToLower(query)); q != "" {
		like := "%" + q + "%"
		where = append(where, "(LOWER(email) LIKE ? OR LOWER(campaign_name) LIKE ? OR LOWER(subject) LIKE ?)")
		args = append(args, like, like, like)
	}
	sqlText := `SELECT id, campaign_id, campaign_name, template_id, email, subject, from_email, variant, status, failure_kind, detail, message_id, created_at FROM send_ledger`
	if len(where) > 0 {
		sqlText += " WHERE " + strings.Join(where, " AND ")
	}
	sqlText += " ORDER BY id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	rows, err := s.db.Query(sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SendLedgerEntry{}
	for rows.Next() {
		var e SendLedgerEntry
		if err := rows.Scan(&e.ID, &e.CampaignID, &e.CampaignName, &e.TemplateID, &e.Email,
			&e.Subject, &e.FromEmail, &e.Variant, &e.Status, &e.FailureKind, &e.Detail, &e.MessageID, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) RecordDeletedCampaign(c DeletedCampaign) error {
	_, err := s.db.Exec(
		`INSERT INTO deleted_campaigns(campaign_id, name, targets, sent, deleted_at) VALUES(?, ?, ?, ?, ?)`,
		c.CampaignID, c.Name, c.Targets, c.Sent, now(),
	)
	return err
}

func (s *Store) ListDeletedCampaigns(limit int) ([]DeletedCampaign, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := s.db.Query(
		`SELECT id, campaign_id, name, targets, sent, deleted_at FROM deleted_campaigns ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeletedCampaign{}
	for rows.Next() {
		var c DeletedCampaign
		if err := rows.Scan(&c.ID, &c.CampaignID, &c.Name, &c.Targets, &c.Sent, &c.DeletedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ChatSearchHit is one durable assistant/tool message matching a query.
type ChatSearchHit struct {
	ID        int64  `json:"id"`
	SessionID int64  `json:"session_id"`
	Title     string `json:"session_title"`
	Role      string `json:"role"`
	Content   string `json:"content"`
	CreatedAt string `json:"created_at"`
}

// SearchChatMessages searches assistant and tool turns only (never user
// input, which may contain credentials). Used as a fallback when the send
// ledger has no rows for a send that predates the ledger.
func (s *Store) SearchChatMessages(query string, limit int) ([]ChatSearchHit, error) {
	q := strings.TrimSpace(strings.ToLower(query))
	if q == "" {
		return []ChatSearchHit{}, nil
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.Query(
		`SELECT m.id, m.session_id, COALESCE(s.title,''), m.role, m.content, m.created_at
		 FROM chat_messages m LEFT JOIN chat_sessions s ON s.id = m.session_id
		 WHERE m.role IN ('assistant','tool') AND LOWER(m.content) LIKE ?
		 ORDER BY m.id DESC LIMIT ?`, "%"+q+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ChatSearchHit{}
	for rows.Next() {
		var h ChatSearchHit
		if err := rows.Scan(&h.ID, &h.SessionID, &h.Title, &h.Role, &h.Content, &h.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
