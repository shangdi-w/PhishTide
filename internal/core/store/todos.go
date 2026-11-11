package store

// Agent task ledger: a small, per-conversation checklist that survives
// context trimming so multi-step work can be resumed.

// AgentTodo is one checklist item.
type AgentTodo struct {
	ID        int64  `json:"id"`
	SessionID int64  `json:"session_id"`
	Text      string `json:"text"`
	Status    string `json:"status"` // pending | in_progress | done
	Position  int    `json:"position"`
	UpdatedAt string `json:"updated_at"`
}

// ReplaceAgentTodos replaces the whole checklist for a session. Items are
// expected to be short and already validated by the caller.
func (s *Store) ReplaceAgentTodos(sessionID int64, items []AgentTodo) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM agent_todos WHERE session_id = ?`, sessionID); err != nil {
		return err
	}
	ts := now()
	for i, it := range items {
		status := it.Status
		switch status {
		case "pending", "in_progress", "done":
		default:
			status = "pending"
		}
		if _, err := tx.Exec(
			`INSERT INTO agent_todos(session_id, text, status, position, updated_at) VALUES(?, ?, ?, ?, ?)`,
			sessionID, it.Text, status, i, ts,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListAgentTodos returns a session's checklist in display order.
func (s *Store) ListAgentTodos(sessionID int64) ([]AgentTodo, error) {
	rows, err := s.db.Query(
		`SELECT id, session_id, text, status, position, updated_at FROM agent_todos WHERE session_id = ? ORDER BY position, id`,
		sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentTodo{}
	for rows.Next() {
		var t AgentTodo
		if err := rows.Scan(&t.ID, &t.SessionID, &t.Text, &t.Status, &t.Position, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
