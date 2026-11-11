package store

// Content version history for email templates and landing pages. Every write
// that goes through the normal store methods leaves a snapshot, so an
// overwrite can always be inspected and rolled back. Payloads are stored as
// JSON so one table serves both object kinds.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Content version kinds.
const (
	VersionEmailTemplate = "email_template"
	VersionLandingPage   = "landing_page"
)

// contentVersionKeep is how many snapshots are retained per object.
const contentVersionKeep = 20

// ContentVersion is one saved snapshot. Payload is omitted from list responses.
type ContentVersion struct {
	ID        int64  `json:"id"`
	Kind      string `json:"kind"`
	ObjectID  int64  `json:"object_id"`
	Name      string `json:"name"`
	Action    string `json:"action"` // create | update | rollback
	Payload   string `json:"-"`
	SizeBytes int    `json:"size_bytes"`
	CreatedAt string `json:"created_at"`
}

// landingPageVersion is the snapshot payload for a page. LandingPage marks
// Body as json:"-" for list responses, so it needs an explicit shape here.
type landingPageVersion struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Kind               string `json:"kind"`
	SourceURL          string `json:"source_url,omitempty"`
	Body               string `json:"body"`
	ContentType        string `json:"content_type"`
	CaptureCredentials bool   `json:"capture_credentials"`
	CapturePasswords   bool   `json:"capture_passwords"`
	RedirectURL        string `json:"redirect_url"`
}

func pageVersionPayload(p LandingPage) landingPageVersion {
	return landingPageVersion{
		ID: p.ID, Name: p.Name, Kind: p.Kind, SourceURL: p.SourceURL, Body: p.Body,
		ContentType: p.ContentType, CaptureCredentials: p.CaptureCredentials,
		CapturePasswords: p.CapturePasswords, RedirectURL: p.RedirectURL,
	}
}

// addContentVersion records a snapshot and trims old ones. It is best-effort:
// a versioning failure must never fail the actual write.
func (s *Store) addContentVersion(kind string, objectID int64, name, action string, payload any) error {
	if objectID <= 0 {
		return nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(
		`INSERT INTO content_versions(kind, object_id, name, action, payload, size_bytes, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		kind, objectID, name, action, string(raw), len(raw), now(),
	); err != nil {
		return err
	}
	s.pruneContentVersions(kind, objectID)
	return nil
}

// pruneContentVersions keeps only the newest contentVersionKeep snapshots of
// an object.
func (s *Store) pruneContentVersions(kind string, objectID int64) {
	rows, err := s.db.Query(
		`SELECT id FROM content_versions WHERE kind = ? AND object_id = ? ORDER BY id DESC`, kind, objectID)
	if err != nil {
		return
	}
	var stale []int64
	n := 0
	for rows.Next() {
		var id int64
		if rows.Scan(&id) != nil {
			rows.Close()
			return
		}
		n++
		if n > contentVersionKeep {
			stale = append(stale, id)
		}
	}
	rows.Close()
	if len(stale) == 0 {
		return
	}
	args := make([]any, len(stale))
	for i, id := range stale {
		args[i] = id
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(stale)), ",")
	_, _ = s.db.Exec(`DELETE FROM content_versions WHERE id IN (`+placeholders+`)`, args...)
}

// ListContentVersions returns an object's snapshots, newest first, without
// payloads.
func (s *Store) ListContentVersions(kind string, objectID int64, limit int) ([]ContentVersion, error) {
	if kind != VersionEmailTemplate && kind != VersionLandingPage {
		return nil, errors.New("未知的版本类型")
	}
	if limit <= 0 || limit > 100 {
		limit = contentVersionKeep
	}
	rows, err := s.db.Query(
		`SELECT id, kind, object_id, name, action, size_bytes, created_at FROM content_versions
		 WHERE kind = ? AND object_id = ? ORDER BY id DESC LIMIT ?`, kind, objectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ContentVersion{}
	for rows.Next() {
		var v ContentVersion
		if err := rows.Scan(&v.ID, &v.Kind, &v.ObjectID, &v.Name, &v.Action, &v.SizeBytes, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetContentVersion returns one snapshot including its payload.
func (s *Store) GetContentVersion(id int64) (ContentVersion, error) {
	var v ContentVersion
	err := s.db.QueryRow(
		`SELECT id, kind, object_id, name, action, payload, size_bytes, created_at FROM content_versions WHERE id = ?`, id).
		Scan(&v.ID, &v.Kind, &v.ObjectID, &v.Name, &v.Action, &v.Payload, &v.SizeBytes, &v.CreatedAt)
	return v, err
}

// RestoreContentVersion writes a snapshot back to its object. The restore is
// itself versioned as "rollback", so it can be undone by restoring again.
func (s *Store) RestoreContentVersion(id int64) (ContentVersion, error) {
	v, err := s.GetContentVersion(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return v, errors.New("版本不存在")
		}
		return v, err
	}
	switch v.Kind {
	case VersionEmailTemplate:
		var t EmailTemplate
		if err := json.Unmarshal([]byte(v.Payload), &t); err != nil {
			return v, fmt.Errorf("版本内容损坏: %w", err)
		}
		if strings.TrimSpace(t.Name) == "" {
			return v, errors.New("版本缺少模板名称")
		}
		res, err := s.db.Exec(`UPDATE email_templates SET name = ?, subject = ?, html = ?, text = ? WHERE id = ?`,
			t.Name, t.Subject, t.HTML, t.Text, v.ObjectID)
		if err != nil {
			return v, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			if _, gerr := s.GetTemplate(v.ObjectID); gerr != nil {
				return v, errors.New("模板已不存在，无法回滚")
			}
		}
		t.ID = v.ObjectID
		_ = s.addContentVersion(VersionEmailTemplate, v.ObjectID, t.Name, "rollback", t)
		return v, nil

	case VersionLandingPage:
		var pv landingPageVersion
		if err := json.Unmarshal([]byte(v.Payload), &pv); err != nil {
			return v, fmt.Errorf("版本内容损坏: %w", err)
		}
		p := LandingPage{
			ID: pv.ID, Name: pv.Name, Kind: pv.Kind, SourceURL: pv.SourceURL, Body: pv.Body,
			ContentType: pv.ContentType, CaptureCredentials: pv.CaptureCredentials,
			CapturePasswords: pv.CapturePasswords, RedirectURL: pv.RedirectURL,
		}
		if strings.TrimSpace(p.Name) == "" {
			return v, errors.New("版本缺少页面名称")
		}
		cc, cp := 0, 0
		if p.CaptureCredentials {
			cc = 1
		}
		if p.CapturePasswords {
			cp = 1
		}
		res, err := s.db.Exec(
			`UPDATE landing_pages SET name = ?, body = ?, capture_credentials = ?, capture_passwords = ?, redirect_url = ? WHERE id = ?`,
			p.Name, p.Body, cc, cp, p.RedirectURL, v.ObjectID)
		if err != nil {
			return v, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			if _, gerr := s.GetPage(v.ObjectID); gerr != nil {
				return v, errors.New("落地页已不存在，无法回滚")
			}
		}
		p.ID = v.ObjectID
		_ = s.addContentVersion(VersionLandingPage, v.ObjectID, p.Name, "rollback", pageVersionPayload(p))
		return v, nil

	default:
		return v, errors.New("未知的版本类型")
	}
}
