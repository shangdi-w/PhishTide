package store

// Referential checks before deleting reusable objects. A template, landing
// page, sending profile or group that an active campaign still points at must
// not be deleted, otherwise that campaign can no longer render or send.

import "strings"

func (s *Store) campaignNamesWhere(query string, args ...any) ([]string, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
		if len(out) >= 10 {
			break
		}
	}
	return out, rows.Err()
}

// CampaignsUsingTemplate lists active campaigns referencing a template as A or
// B.
func (s *Store) CampaignsUsingTemplate(id int64) ([]string, error) {
	return s.campaignNamesWhere(
		`SELECT name FROM campaigns WHERE email_template_id = ? OR email_template_b_id = ? ORDER BY id`,
		id, id)
}

// CampaignsUsingPage lists active campaigns referencing a landing page.
func (s *Store) CampaignsUsingPage(id int64) ([]string, error) {
	return s.campaignNamesWhere(
		`SELECT name FROM campaigns WHERE landing_page_id = ? ORDER BY id`, id)
}

// CampaignsUsingProfile lists active campaigns referencing a sending profile.
func (s *Store) CampaignsUsingProfile(id int64) ([]string, error) {
	return s.campaignNamesWhere(
		`SELECT name FROM campaigns WHERE sending_profile_id = ? ORDER BY id`, id)
}

// CampaignsUsingGroup lists active campaigns linked to a target group.
func (s *Store) CampaignsUsingGroup(id int64) ([]string, error) {
	return s.campaignNamesWhere(
		`SELECT c.name FROM campaigns c JOIN campaign_groups cg ON cg.campaign_id = c.id
		 WHERE cg.group_id = ? ORDER BY c.id`, id)
}

// ReferencedBy renders campaign names for an error message.
func ReferencedBy(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return "「" + strings.Join(names, "、") + "」"
}
