package store

// Cross-resource search for the operator console. Each resource returns a
// short snippet around the first match; callers redact secrets before display.

import "strings"

type SearchHit struct {
	Kind    string `json:"kind"` // session|template|page|campaign|ledger|submission
	RefID   int64  `json:"ref_id"`
	Title   string `json:"title"`
	Snippet string `json:"snippet"`
	Meta    string `json:"meta,omitempty"`
	At      string `json:"at,omitempty"`
}

func snippetAround(text, query string, width int) string {
	if width <= 0 {
		width = 160
	}
	lower := strings.ToLower(text)
	q := strings.ToLower(query)
	idx := strings.Index(lower, q)
	if idx < 0 {
		idx = 0
	}
	// Convert the byte index to a rune offset so Chinese text is not split.
	startRune := len([]rune(text[:idx])) - width/2
	if startRune < 0 {
		startRune = 0
	}
	r := []rune(text)
	end := startRune + width
	if end > len(r) {
		end = len(r)
	}
	out := strings.Join(strings.Fields(string(r[startRune:end])), " ")
	if startRune > 0 {
		out = "…" + out
	}
	if end < len(r) {
		out += "…"
	}
	return out
}

// GlobalSearch searches sessions, templates, pages, campaigns, the send ledger
// and submissions. perType bounds results per resource (default 8, max 20).
func (s *Store) GlobalSearch(query string, perType int) ([]SearchHit, error) {
	q := strings.TrimSpace(query)
	if q == "" {
		return []SearchHit{}, nil
	}
	if perType <= 0 {
		perType = 8
	}
	if perType > 20 {
		perType = 20
	}
	lower := "%" + strings.ToLower(q) + "%"
	out := []SearchHit{}

	// Sessions: assistant/tool/user messages, newest first.
	rows, err := s.db.Query(`SELECT m.session_id, COALESCE(s.title,''), m.role, m.content, m.created_at
		FROM chat_messages m LEFT JOIN chat_sessions s ON s.id = m.session_id
		WHERE LOWER(m.content) LIKE ? ORDER BY m.id DESC LIMIT ?`, lower, perType)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sid int64
		var role, content, at, title string
		if rows.Scan(&sid, &title, &role, &content, &at) == nil {
			if title == "" {
				title = "未命名会话"
			}
			out = append(out, SearchHit{Kind: "session", RefID: sid, Title: title,
				Snippet: snippetAround(content, q, 180), Meta: role, At: at})
		}
	}
	rows.Close()

	// Email templates.
	rows, err = s.db.Query(`SELECT id, name, subject, html FROM email_templates
		WHERE LOWER(name) LIKE ? OR LOWER(subject) LIKE ? OR LOWER(html) LIKE ? ORDER BY id DESC LIMIT ?`,
		lower, lower, lower, perType)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var name, subject, html string
		if rows.Scan(&id, &name, &subject, &html) == nil {
			text := subject
			if !strings.Contains(strings.ToLower(subject), strings.ToLower(q)) {
				text = html
			}
			out = append(out, SearchHit{Kind: "template", RefID: id, Title: name,
				Snippet: snippetAround(text, q, 180), Meta: subject})
		}
	}
	rows.Close()

	// Landing pages.
	rows, err = s.db.Query(`SELECT id, name, kind, source_url, body FROM landing_pages
		WHERE LOWER(name) LIKE ? OR LOWER(source_url) LIKE ? OR LOWER(body) LIKE ? ORDER BY id DESC LIMIT ?`,
		lower, lower, lower, perType)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var name, kind, sourceURL, body string
		if rows.Scan(&id, &name, &kind, &sourceURL, &body) == nil {
			text := body
			if strings.Contains(strings.ToLower(name), strings.ToLower(q)) || strings.Contains(strings.ToLower(sourceURL), strings.ToLower(q)) {
				text = name + " " + sourceURL
			}
			out = append(out, SearchHit{Kind: "page", RefID: id, Title: name,
				Snippet: snippetAround(text, q, 180), Meta: kind})
		}
	}
	rows.Close()

	// Campaigns.
	rows, err = s.db.Query(`SELECT id, name, status, created_at FROM campaigns
		WHERE LOWER(name) LIKE ? ORDER BY id DESC LIMIT ?`, lower, perType)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var name, status, at string
		if rows.Scan(&id, &name, &status, &at) == nil {
			out = append(out, SearchHit{Kind: "campaign", RefID: id, Title: name,
				Snippet: name, Meta: status, At: at})
		}
	}
	rows.Close()

	// Send ledger.
	rows, err = s.db.Query(`SELECT campaign_id, campaign_name, email, subject, status, message_id, created_at
		FROM send_ledger WHERE LOWER(campaign_name) LIKE ? OR LOWER(email) LIKE ? OR LOWER(subject) LIKE ? OR LOWER(message_id) LIKE ?
		ORDER BY id DESC LIMIT ?`, lower, lower, lower, lower, perType)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var cid int64
		var cname, email, subject, status, mid, at string
		if rows.Scan(&cid, &cname, &email, &subject, &status, &mid, &at) == nil {
			out = append(out, SearchHit{Kind: "ledger", RefID: cid, Title: cname + " → " + email,
				Snippet: snippetAround(subject+" "+mid, q, 180), Meta: status, At: at})
		}
	}
	rows.Close()

	// Submissions (credentials redacted by the caller).
	rows, err = s.db.Query(`SELECT s.campaign_id, COALESCE(c.name,''), s.username, s.fields, s.ts, COALESCE(t.email,'')
		FROM submissions s
		LEFT JOIN campaigns c ON c.id = s.campaign_id
		LEFT JOIN results r ON r.id = s.result_id
		LEFT JOIN targets t ON t.id = r.target_id
		WHERE LOWER(s.username) LIKE ? OR LOWER(s.fields) LIKE ? OR LOWER(t.email) LIKE ?
		ORDER BY s.id DESC LIMIT ?`, lower, lower, lower, perType)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var cid int64
		var cname, username, fields, at, email string
		if rows.Scan(&cid, &cname, &username, &fields, &at, &email) == nil {
			title := username
			if title == "" {
				title = email
			}
			out = append(out, SearchHit{Kind: "submission", RefID: cid, Title: title,
				Snippet: snippetAround(fields, q, 180), Meta: cname, At: at})
		}
	}
	rows.Close()
	return out, nil
}
