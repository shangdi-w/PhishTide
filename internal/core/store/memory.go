package store

// Long-term memories the console agent keeps across chat sessions: operator
// preferences, fixed sending details and other facts that should survive a
// session being closed.

import (
	"strings"
	"time"
)

// AgentMemory is one keyed fact saved by the console agent.
type AgentMemory struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Category  string `json:"category"`
	UpdatedAt string `json:"updated_at"`
}

// UpsertAgentMemory creates or replaces one memory entry.
func (s *Store) UpsertAgentMemory(key, value, category string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if category != "preference" && category != "task" {
		category = "fact"
	}
	_, err := s.db.Exec(s.sql(
		`INSERT INTO agent_memories(mem_key, value, category, updated_at) VALUES(?, ?, ?, ?)
		 ON CONFLICT(mem_key) DO UPDATE SET value = excluded.value, category = excluded.category, updated_at = excluded.updated_at`,
		`INSERT INTO agent_memories(mem_key, value, category, updated_at) VALUES(?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE value = VALUES(value), category = VALUES(category), updated_at = VALUES(updated_at)`,
	), key, value, category, now)
	return err
}

// ListAgentMemories returns memories newest first.
func (s *Store) ListAgentMemories(limit int) ([]AgentMemory, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT mem_key, value, category, updated_at FROM agent_memories ORDER BY updated_at DESC, mem_key LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentMemory
	for rows.Next() {
		var m AgentMemory
		if err := rows.Scan(&m.Key, &m.Value, &m.Category, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// SearchAgentMemories matches key or value against a substring, newest first.
func (s *Store) SearchAgentMemories(query string, limit int) ([]AgentMemory, error) {
	if limit <= 0 {
		limit = 30
	}
	q := "%" + strings.TrimSpace(query) + "%"
	rows, err := s.db.Query(`SELECT mem_key, value, category, updated_at FROM agent_memories
		WHERE mem_key LIKE ? OR value LIKE ? ORDER BY updated_at DESC, mem_key LIMIT ?`, q, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentMemory
	for rows.Next() {
		var m AgentMemory
		if err := rows.Scan(&m.Key, &m.Value, &m.Category, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteAgentMemory removes one entry and reports whether it existed.
func (s *Store) DeleteAgentMemory(key string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM agent_memories WHERE mem_key = ?`, key)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// CountAgentMemories returns the number of saved memories.
func (s *Store) CountAgentMemories() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM agent_memories`).Scan(&n)
	return n, err
}
