package store

import "database/sql"

// Email template attachments and console chat persistence (sessions, turns,
// uploads). Kept in its own file because store.go is already large.

// UpdateTemplate updates an existing template in place (id-keyed, so renaming
// does not create a second row like UpsertTemplate would).
func (s *Store) UpdateTemplate(t EmailTemplate) error {
	if t.ID <= 0 {
		return sql.ErrNoRows
	}
	res, err := s.db.Exec(`UPDATE email_templates SET name = ?, subject = ?, html = ?, text = ? WHERE id = ?`,
		t.Name, t.Subject, t.HTML, t.Text, t.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.GetTemplate(t.ID); err != nil {
			return sql.ErrNoRows
		}
	}
	_ = s.addContentVersion(VersionEmailTemplate, t.ID, t.Name, "update", t)
	return nil
}

// UpdatePage updates an existing landing page in place, keeping its kind,
// source URL, content type and mirrored assets.
func (s *Store) UpdatePage(p LandingPage) error {
	if p.ID <= 0 {
		return sql.ErrNoRows
	}
	cc, cp := 0, 0
	if p.CaptureCredentials {
		cc = 1
	}
	if p.CapturePasswords {
		cp = 1
	}
	res, err := s.db.Exec(`UPDATE landing_pages SET name = ?, body = ?, capture_credentials = ?, capture_passwords = ?, redirect_url = ? WHERE id = ?`,
		p.Name, p.Body, cc, cp, p.RedirectURL, p.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.GetPage(p.ID); err != nil {
			return sql.ErrNoRows
		}
	}
	_ = s.addContentVersion(VersionLandingPage, p.ID, p.Name, "update", pageVersionPayload(p))
	return nil
}

// TemplateAttachment is one file attached to an email template. Body is only
// populated by the download/send helpers; list endpoints return metadata.
type TemplateAttachment struct {
	ID          int64  `json:"id"`
	TemplateID  int64  `json:"template_id"`
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Body        []byte `json:"-"`
}

// ListTemplateAttachments returns attachment metadata for one template.
func (s *Store) ListTemplateAttachments(templateID int64) ([]TemplateAttachment, error) {
	rows, err := s.db.Query(`SELECT id, template_id, name, content_type, size_bytes FROM template_attachments WHERE template_id = ? ORDER BY id`, templateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TemplateAttachment{}
	for rows.Next() {
		var a TemplateAttachment
		if err := rows.Scan(&a.ID, &a.TemplateID, &a.Name, &a.ContentType, &a.Size); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// TemplateAttachmentsWithBody returns every attachment of a template including
// its bytes, for building the outgoing message.
func (s *Store) TemplateAttachmentsWithBody(templateID int64) ([]TemplateAttachment, error) {
	rows, err := s.db.Query(`SELECT id, template_id, name, content_type, size_bytes, body FROM template_attachments WHERE template_id = ? ORDER BY id`, templateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TemplateAttachment{}
	for rows.Next() {
		var a TemplateAttachment
		if err := rows.Scan(&a.ID, &a.TemplateID, &a.Name, &a.ContentType, &a.Size, &a.Body); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AddTemplateAttachment stores one attachment.
func (s *Store) AddTemplateAttachment(a TemplateAttachment) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO template_attachments(template_id, name, content_type, size_bytes, body) VALUES(?, ?, ?, ?, ?)`,
		a.TemplateID, a.Name, a.ContentType, int64(len(a.Body)), a.Body)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ---------------------------------------------------------------------------
// Console chat sessions

// ChatSession is one persisted console conversation.
type ChatSession struct {
	ID        int64  `json:"id"`
	Title     string `json:"title"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Messages  int    `json:"messages,omitempty"`
}

// ChatMessage is one persisted turn. Data holds the full provider message
// (tool calls and tool results included) so the conversation can be replayed.
type ChatMessage struct {
	ID        int64  `json:"id"`
	SessionID int64  `json:"session_id"`
	Role      string `json:"role"`
	Content   string `json:"content"`
	Data      string `json:"-"`
	CreatedAt string `json:"created_at"`
}

// CreateChatSession creates a conversation and returns its id.
func (s *Store) CreateChatSession(title string) (int64, error) {
	ts := now()
	res, err := s.db.Exec(`INSERT INTO chat_sessions(title, created_at, updated_at) VALUES(?, ?, ?)`, title, ts, ts)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListChatSessions returns conversations, newest first, with message counts.
func (s *Store) ListChatSessions(limit int) ([]ChatSession, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT s.id, s.title, s.created_at, s.updated_at,
		(SELECT COUNT(*) FROM chat_messages m WHERE m.session_id = s.id)
		FROM chat_sessions s ORDER BY s.updated_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ChatSession{}
	for rows.Next() {
		var c ChatSession
		if err := rows.Scan(&c.ID, &c.Title, &c.CreatedAt, &c.UpdatedAt, &c.Messages); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetChatSession returns one conversation.
func (s *Store) GetChatSession(id int64) (ChatSession, error) {
	var c ChatSession
	err := s.db.QueryRow(`SELECT s.id, s.title, s.created_at, s.updated_at,
		(SELECT COUNT(*) FROM chat_messages m WHERE m.session_id = s.id)
		FROM chat_sessions s WHERE s.id = ?`, id).Scan(&c.ID, &c.Title, &c.CreatedAt, &c.UpdatedAt, &c.Messages)
	return c, err
}

// RenameChatSession updates a conversation title.
func (s *Store) RenameChatSession(id int64, title string) error {
	_, err := s.db.Exec(`UPDATE chat_sessions SET title = ?, updated_at = ? WHERE id = ?`, title, now(), id)
	return err
}

// DeleteChatSession removes a conversation, its messages and its uploads.
func (s *Store) DeleteChatSession(id int64) error {
	for _, q := range []string{
		`DELETE FROM chat_messages WHERE session_id = ?`,
		`DELETE FROM chat_uploads WHERE session_id = ?`,
		`DELETE FROM chat_sessions WHERE id = ?`,
	} {
		if _, err := s.db.Exec(q, id); err != nil {
			return err
		}
	}
	return nil
}

// AppendChatMessage stores one turn and bumps the session timestamp.
func (s *Store) AppendChatMessage(sessionID int64, role, content, data string) (int64, error) {
	ts := now()
	res, err := s.db.Exec(`INSERT INTO chat_messages(session_id, role, content, data, created_at) VALUES(?, ?, ?, ?, ?)`,
		sessionID, role, content, data, ts)
	if err != nil {
		return 0, err
	}
	_, _ = s.db.Exec(`UPDATE chat_sessions SET updated_at = ? WHERE id = ?`, ts, sessionID)
	return res.LastInsertId()
}

// ListChatMessages returns a conversation's turns in order.
func (s *Store) ListChatMessages(sessionID int64) ([]ChatMessage, error) {
	rows, err := s.db.Query(`SELECT id, session_id, role, content, data, created_at FROM chat_messages WHERE session_id = ? ORDER BY id`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ChatMessage{}
	for rows.Next() {
		var m ChatMessage
		if err := rows.Scan(&m.ID, &m.SessionID, &m.Role, &m.Content, &m.Data, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Chat uploads (files attached to a console conversation)

// ChatUpload is a file uploaded from the console chat (recipient CSV, email
// attachment, reference HTML).
type ChatUpload struct {
	ID          int64  `json:"id"`
	SessionID   int64  `json:"session_id"`
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Body        []byte `json:"-"`
	CreatedAt   string `json:"created_at"`
}

// AddChatUpload stores one uploaded file.
func (s *Store) AddChatUpload(u ChatUpload) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO chat_uploads(session_id, name, content_type, size_bytes, body, created_at) VALUES(?, ?, ?, ?, ?, ?)`,
		u.SessionID, u.Name, u.ContentType, int64(len(u.Body)), u.Body, now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetChatUpload returns one upload including its bytes.
func (s *Store) GetChatUpload(id int64) (ChatUpload, error) {
	var u ChatUpload
	err := s.db.QueryRow(`SELECT id, session_id, name, content_type, size_bytes, body, created_at FROM chat_uploads WHERE id = ?`, id).
		Scan(&u.ID, &u.SessionID, &u.Name, &u.ContentType, &u.Size, &u.Body, &u.CreatedAt)
	return u, err
}

// ListChatUploads returns the uploads of one conversation.
func (s *Store) ListChatUploads(sessionID int64) ([]ChatUpload, error) {
	rows, err := s.db.Query(`SELECT id, session_id, name, content_type, size_bytes, created_at FROM chat_uploads WHERE session_id = ? ORDER BY id`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ChatUpload{}
	for rows.Next() {
		var u ChatUpload
		if err := rows.Scan(&u.ID, &u.SessionID, &u.Name, &u.ContentType, &u.Size, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
