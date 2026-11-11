package store

// Adding recipients to an existing campaign. New targets go into a dedicated
// per-campaign group so the original target groups (and other campaigns that
// share them) are never modified. Each new target gets its own result row and
// tracking rid, so links and statistics work exactly like the original set.

import (
	"database/sql"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"strings"
)

// AddCampaignTargets appends recipients to a campaign. Duplicate emails
// (case-insensitive, including targets already in the campaign) are skipped.
func (s *Store) AddCampaignTargets(campaignID int64, targets []Target) (added, skipped int, err error) {
	camp, err := s.GetCampaign(campaignID)
	if err != nil {
		return 0, 0, fmt.Errorf("活动不存在")
	}
	if camp.Status == "terminated" {
		return 0, 0, errors.New("活动已终止，不能追加目标")
	}
	if len(targets) == 0 {
		return 0, 0, errors.New("没有可添加的目标")
	}
	if len(targets) > 1000 {
		return 0, 0, errors.New("单次最多添加 1000 个目标")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()

	// Existing recipients in this campaign (drain before writing: MySQL does
	// not allow interleaving statements on one connection).
	seen := map[string]bool{}
	rows, err := tx.Query(`SELECT LOWER(t.email) FROM results r JOIN targets t ON t.id = r.target_id WHERE r.campaign_id = ?`, campaignID)
	if err != nil {
		return 0, 0, err
	}
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			rows.Close()
			return 0, 0, err
		}
		seen[strings.TrimSpace(email)] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}

	groupName := fmt.Sprintf("活动 %d 追加目标", campaignID)
	var gid int64
	err = tx.QueryRow(`SELECT id FROM target_groups WHERE name = ?`, groupName).Scan(&gid)
	if err == sql.ErrNoRows {
		res, ierr := tx.Exec(`INSERT INTO target_groups(name, created_at) VALUES (?, ?)`, groupName, now())
		if ierr != nil {
			return 0, 0, ierr
		}
		gid, ierr = res.LastInsertId()
		if ierr != nil {
			return 0, 0, ierr
		}
	} else if err != nil {
		return 0, 0, err
	}
	if _, err := tx.Exec(s.sql(
		`INSERT OR IGNORE INTO campaign_groups(campaign_id, group_id) VALUES (?, ?)`,
		`INSERT IGNORE INTO campaign_groups(campaign_id, group_id) VALUES (?, ?)`), campaignID, gid); err != nil {
		return 0, 0, err
	}

	for _, t := range targets {
		email := strings.TrimSpace(t.Email)
		key := strings.ToLower(email)
		// Reject malformed addresses at the storage boundary: a CR/LF here
		// would otherwise reach the SMTP envelope and the To header.
		if !validTargetEmail(email) {
			skipped++
			continue
		}
		if seen[key] {
			skipped++
			continue
		}
		seen[key] = true
		res, err := tx.Exec(
			`INSERT INTO targets(group_id, email, first_name, last_name, position, department) VALUES (?, ?, ?, ?, ?, ?)`,
			gid, email, strings.TrimSpace(t.FirstName), strings.TrimSpace(t.LastName),
			strings.TrimSpace(t.Position), strings.TrimSpace(t.Department),
		)
		if err != nil {
			return 0, 0, err
		}
		targetID, err := res.LastInsertId()
		if err != nil {
			return 0, 0, err
		}
		variant := "A"
		if camp.EmailTemplateBID > 0 {
			split := camp.ABSplit
			if split < 0 || split > 100 {
				split = 50
			}
			if mrand.IntN(100) >= split {
				variant = "B"
			}
		}
		if _, err := tx.Exec(`INSERT INTO results(campaign_id, target_id, rid, variant, status, sent, opened, clicked, submitted, reported, unsubscribed, sent_at, opened_at, clicked_at, submitted_at, reported_at, unsubscribed_at, ip, user_agent) VALUES (?, ?, ?, ?, 'sending', 0, 0, 0, 0, 0, 0, '', '', '', '', '', '', '', '')`,
			campaignID, targetID, newRid(), variant); err != nil {
			return 0, 0, err
		}
		added++
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return added, skipped, nil
}
