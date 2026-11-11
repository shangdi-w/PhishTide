package store

// Bulk deletion for captured submissions.

import "strings"

func (s *Store) DeleteSubmissions(campaignID int64, ids []int64) (int, error) {
	if campaignID <= 0 || len(ids) == 0 {
		return 0, nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, 0, len(ids)+1)
	args = append(args, campaignID)
	for _, id := range ids {
		args = append(args, id)
	}
	res, err := s.db.Exec(`DELETE FROM submissions WHERE campaign_id = ? AND id IN (`+ph+`)`, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
