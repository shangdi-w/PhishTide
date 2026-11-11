package store

// Per-recipient delivery failures. One row per campaign/result: a later attempt
// replaces the previous reason, so the list always reflects the last failure
// and a successful resend clears it.

import (
	"strings"
)

// SendFailure is one failed delivery.
type SendFailure struct {
	ID         int64  `json:"id"`
	CampaignID int64  `json:"campaign_id"`
	ResultID   int64  `json:"result_id"`
	Email      string `json:"email"`
	Kind       string `json:"kind"` // hard | soft | throttle | auth | tls | dns | network | build | render | unknown
	Error      string `json:"error"`
	Attempts   int    `json:"attempts"`
	CreatedAt  string `json:"created_at"`
}

const sendFailureMaxText = 1000

// RecordSendFailure stores (or replaces) the latest failure of one recipient.
func (s *Store) RecordSendFailure(f SendFailure) error {
	if f.Attempts <= 0 {
		f.Attempts = 1
	}
	text := strings.TrimSpace(f.Error)
	if len(text) > sendFailureMaxText {
		text = text[:sendFailureMaxText]
	}
	if f.ResultID > 0 {
		_, _ = s.db.Exec(`DELETE FROM send_failures WHERE campaign_id = ? AND result_id = ?`, f.CampaignID, f.ResultID)
	}
	_, err := s.db.Exec(
		`INSERT INTO send_failures(campaign_id, result_id, email, kind, error, attempts, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		f.CampaignID, f.ResultID, f.Email, f.Kind, text, f.Attempts, now())
	return err
}

// ClearSendFailure removes the failure row for a recipient after it succeeds.
func (s *Store) ClearSendFailure(campaignID, resultID int64) error {
	if resultID <= 0 {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM send_failures WHERE campaign_id = ? AND result_id = ?`, campaignID, resultID)
	return err
}

// ListSendFailures returns a campaign's failures, newest first.
func (s *Store) ListSendFailures(campaignID int64, limit int) ([]SendFailure, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.Query(
		`SELECT id, campaign_id, result_id, email, kind, error, attempts, created_at
		 FROM send_failures WHERE campaign_id = ? ORDER BY id DESC LIMIT ?`, campaignID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SendFailure{}
	for rows.Next() {
		var f SendFailure
		if err := rows.Scan(&f.ID, &f.CampaignID, &f.ResultID, &f.Email, &f.Kind, &f.Error, &f.Attempts, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
