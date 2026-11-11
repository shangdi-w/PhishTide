package store

// Delivery status notifications (DSN bounces). A bounce is the relay's verdict
// on an earlier send: a hard 5.x.x bounce means the mailbox is gone and the
// address should be treated as invalid, a 4.x.x bounce is temporary. The
// importer keeps the latest verdict per recipient so a delayed notice can be
// superseded by the final failure.

import "strings"

// Bounce is one per-recipient delivery status notification.
type Bounce struct {
	ID         int64  `json:"id"`
	CampaignID int64  `json:"campaign_id"`
	ResultID   int64  `json:"result_id"`
	Email      string `json:"email"`
	Kind       string `json:"kind"`       // hard | soft | delivered
	Action     string `json:"action"`     // failed | delayed | delivered
	Status     string `json:"status"`     // enhanced status code, e.g. 5.1.1
	Diagnostic string `json:"diagnostic"` // SMTP diagnostic text
	CreatedAt  string `json:"created_at"`
}

const bounceMaxDiagnostic = 800

// RecordBounce stores the latest bounce for one result, replacing an earlier
// one. A result with resultID 0 (unmatched sender) is only inserted as-is.
func (s *Store) RecordBounce(b Bounce) error {
	text := strings.TrimSpace(b.Diagnostic)
	if len(text) > bounceMaxDiagnostic {
		text = text[:bounceMaxDiagnostic]
	}
	if b.ResultID > 0 {
		_, _ = s.db.Exec(`DELETE FROM bounces WHERE campaign_id = ? AND result_id = ?`, b.CampaignID, b.ResultID)
	}
	_, err := s.db.Exec(
		`INSERT INTO bounces(campaign_id, result_id, email, kind, action, status, diagnostic, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		b.CampaignID, b.ResultID, b.Email, b.Kind, b.Action, b.Status, text, now())
	return err
}

// ListBounces returns a campaign's bounces, newest first.
func (s *Store) ListBounces(campaignID int64, limit int) ([]Bounce, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.Query(
		`SELECT id, campaign_id, result_id, email, kind, action, status, diagnostic, created_at
		 FROM bounces WHERE campaign_id = ? ORDER BY id DESC LIMIT ?`, campaignID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Bounce{}
	for rows.Next() {
		var b Bounce
		if err := rows.Scan(&b.ID, &b.CampaignID, &b.ResultID, &b.Email, &b.Kind,
			&b.Action, &b.Status, &b.Diagnostic, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ListAllBounces returns bounces across campaigns, newest first.
func (s *Store) ListAllBounces(limit int) ([]Bounce, error) {
	if limit <= 0 || limit > 1000 {
		limit = 300
	}
	rows, err := s.db.Query(
		`SELECT id, campaign_id, result_id, email, kind, action, status, diagnostic, created_at
		 FROM bounces ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Bounce{}
	for rows.Next() {
		var b Bounce
		if err := rows.Scan(&b.ID, &b.CampaignID, &b.ResultID, &b.Email, &b.Kind,
			&b.Action, &b.Status, &b.Diagnostic, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// CountBouncesByKind returns hard/soft/delivered totals for a campaign.
func (s *Store) CountBouncesByKind(campaignID int64) (map[string]int, error) {
	rows, err := s.db.Query(`SELECT kind, COUNT(*) FROM bounces WHERE campaign_id = ? GROUP BY kind`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// FindResultByEmail returns the most recent sent result for an address, used to
// attribute a DSN to the campaign that produced it. Addresses are compared
// case-insensitively; results only exist for recipients that were sent to.
func (s *Store) FindResultByEmail(email string) (Result, error) {
	var r Result
	err := s.db.QueryRow(`
		SELECT r.id, r.campaign_id, r.target_id, r.rid, r.variant, r.status, r.sent, r.opened, r.clicked,
		       r.submitted, r.reported, r.unsubscribed, r.sent_at, r.opened_at, r.clicked_at, r.submitted_at,
		       r.reported_at, r.unsubscribed_at, r.ip, r.user_agent,
		       t.email, t.first_name, t.last_name, t.position, t.department
		FROM results r JOIN targets t ON t.id = r.target_id
		WHERE LOWER(t.email) = LOWER(?) AND r.sent = 1
		ORDER BY r.id DESC LIMIT 1`, strings.TrimSpace(email)).
		Scan(&r.ID, &r.CampaignID, &r.TargetID, &r.Rid, &r.Variant, &r.Status,
			&r.Sent, &r.Opened, &r.Clicked, &r.Submitted, &r.Reported, &r.Unsubscribed,
			&r.SentAt, &r.OpenedAt, &r.ClickedAt, &r.SubmittedAt, &r.ReportedAt, &r.UnsubscribedAt,
			&r.IP, &r.UserAgent, &r.Email, &r.FirstName, &r.LastName, &r.Position, &r.Department)
	return r, err
}

// MarkBounced flags a result's delivery status for display.
func (s *Store) MarkBounced(resultID int64, kind string) {
	status := "bounced"
	if kind == "soft" {
		status = "delayed"
	}
	_, _ = s.db.Exec(`UPDATE results SET status = ? WHERE id = ?`, status, resultID)
}
