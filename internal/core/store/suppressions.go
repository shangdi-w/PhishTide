package store

// Cross-campaign suppression list: hard bounces, unsubscribes and manual
// entries are skipped before any future send.

import (
	"strings"
)

type Suppression struct {
	Email     string `json:"email"`
	Reason    string `json:"reason"`
	Note      string `json:"note"`
	CreatedAt string `json:"created_at"`
}

func normalizeEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

func (s *Store) UpsertSuppression(email, reason, note string) error {
	e := normalizeEmail(email)
	if e == "" || !strings.Contains(e, "@") {
		return nil
	}
	if reason == "" {
		reason = "manual"
	}
	_, err := s.db.Exec(s.sql(
		`INSERT INTO suppressions(email, reason, note, created_at) VALUES(?, ?, ?, ?)
		 ON CONFLICT(email) DO UPDATE SET reason = excluded.reason, note = excluded.note`,
		`INSERT INTO suppressions(email, reason, note, created_at) VALUES(?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE reason = VALUES(reason), note = VALUES(note)`),
		e, reason, note, now())
	return err
}

func (s *Store) ListSuppressions(limit int) ([]Suppression, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT email, reason, note, created_at FROM suppressions ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Suppression{}
	for rows.Next() {
		var x Suppression
		if err := rows.Scan(&x.Email, &x.Reason, &x.Note, &x.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSuppression(email string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM suppressions WHERE email = ?`, normalizeEmail(email))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SuppressionSet returns lower-cased suppressed addresses for send loops.
func (s *Store) SuppressionSet() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT email FROM suppressions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var e string
		if rows.Scan(&e) == nil {
			out[normalizeEmail(e)] = true
		}
	}
	return out, rows.Err()
}
