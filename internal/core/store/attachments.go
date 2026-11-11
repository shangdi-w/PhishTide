package store

// Isolated payload attachment store. Files live only in the database, sealed
// with the platform secret key when configured. Nothing in the platform opens,
// parses, previews or executes them; they are read only when the SMTP sender
// base64-encodes them into a message.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"phishsim/internal/core/crypto"
)

// PayloadAttachment is one uploaded file's metadata (never its bytes).
type PayloadAttachment struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	SizeBytes   int64  `json:"size_bytes"`
	SHA256      string `json:"sha256"`
	Note        string `json:"note"`
	CreatedAt   string `json:"created_at"`
}

func (s *Store) sealPayload(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return []byte{}, nil
	}
	if len(s.secretKey) == 0 {
		return body, nil
	}
	return crypto.EncryptBytes(body, s.secretKey)
}

func (s *Store) openPayload(sealed []byte) []byte {
	if len(sealed) == 0 || len(s.secretKey) == 0 {
		return sealed
	}
	if plain, err := crypto.DecryptBytes(sealed, s.secretKey); err == nil {
		return plain
	}
	// Legacy/plain rows: fall back to the stored bytes.
	return sealed
}

// AddPayloadAttachment stores one file and returns its id.
func (s *Store) AddPayloadAttachment(a PayloadAttachment, body []byte) (int64, error) {
	if a.Name == "" {
		return 0, errors.New("attachment name required")
	}
	sealed, err := s.sealPayload(body)
	if err != nil {
		return 0, err
	}
	sum := sha256.Sum256(body)
	a.SHA256 = hex.EncodeToString(sum[:])
	a.SizeBytes = int64(len(body))
	res, err := s.db.Exec(
		`INSERT INTO payload_attachments(name, content_type, size_bytes, sha256, note, body, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		a.Name, a.ContentType, a.SizeBytes, a.SHA256, a.Note, sealed, now(),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListPayloadAttachments returns metadata newest first.
func (s *Store) ListPayloadAttachments() ([]PayloadAttachment, error) {
	rows, err := s.db.Query(
		`SELECT id, name, content_type, size_bytes, sha256, note, created_at FROM payload_attachments ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PayloadAttachment{}
	for rows.Next() {
		var a PayloadAttachment
		if err := rows.Scan(&a.ID, &a.Name, &a.ContentType, &a.SizeBytes, &a.SHA256, &a.Note, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetPayloadAttachment returns one file with its decrypted bytes.
func (s *Store) GetPayloadAttachment(id int64) (PayloadAttachment, []byte, error) {
	var a PayloadAttachment
	var sealed []byte
	err := s.db.QueryRow(
		`SELECT id, name, content_type, size_bytes, sha256, note, created_at, body FROM payload_attachments WHERE id = ?`, id,
	).Scan(&a.ID, &a.Name, &a.ContentType, &a.SizeBytes, &a.SHA256, &a.Note, &a.CreatedAt, &sealed)
	if err != nil {
		return a, nil, err
	}
	return a, s.openPayload(sealed), nil
}

// DeletePayloadAttachment removes one file. Template copies are independent.
func (s *Store) DeletePayloadAttachment(id int64) error {
	_, err := s.db.Exec(`DELETE FROM payload_attachments WHERE id = ?`, id)
	return err
}
