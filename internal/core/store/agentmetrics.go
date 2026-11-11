package store

// Per-session agent telemetry: token usage, tool calls/errors and latency.
// Kept separate from llm_usage so model-call accounting stays append-only.

import "time"

// AgentMetrics aggregates one conversation's agent activity.
type AgentMetrics struct {
	SessionID        int64  `json:"session_id"`
	Runs             int64  `json:"runs"`
	Rounds           int64  `json:"rounds"`
	ToolCalls        int64  `json:"tool_calls"`
	ToolErrors       int64  `json:"tool_errors"`
	PromptTokens     int64  `json:"prompt_tokens"`
	CompletionTokens int64  `json:"completion_tokens"`
	TotalTokens      int64  `json:"total_tokens"`
	LastDurationMs   int64  `json:"last_duration_ms"`
	LastRunAt        string `json:"last_run_at"`
}

// MergeAgentMetrics adds one run's counters to the session totals and appends
// an immutable run row for history charts.
func (s *Store) MergeAgentMetrics(sessionID int64, rounds, toolCalls, toolErrors int, durationMs, prompt, completion, total int64) error {
	if sessionID <= 0 {
		return nil
	}
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.Exec(s.sql(
		`INSERT INTO agent_metrics(session_id, runs, rounds, tool_calls, tool_errors, prompt_tokens, completion_tokens, total_tokens, last_duration_ms, last_run_at)
		 VALUES(?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(session_id) DO UPDATE SET
		   runs = runs + 1, rounds = rounds + excluded.rounds,
		   tool_calls = tool_calls + excluded.tool_calls, tool_errors = tool_errors + excluded.tool_errors,
		   prompt_tokens = prompt_tokens + excluded.prompt_tokens,
		   completion_tokens = completion_tokens + excluded.completion_tokens,
		   total_tokens = total_tokens + excluded.total_tokens,
		   last_duration_ms = excluded.last_duration_ms, last_run_at = excluded.last_run_at`,
		`INSERT INTO agent_metrics(session_id, runs, rounds, tool_calls, tool_errors, prompt_tokens, completion_tokens, total_tokens, last_duration_ms, last_run_at)
		 VALUES(?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE
		   runs = runs + 1, rounds = rounds + VALUES(rounds),
		   tool_calls = tool_calls + VALUES(tool_calls), tool_errors = tool_errors + VALUES(tool_errors),
		   prompt_tokens = prompt_tokens + VALUES(prompt_tokens),
		   completion_tokens = completion_tokens + VALUES(completion_tokens),
		   total_tokens = total_tokens + VALUES(total_tokens),
		   last_duration_ms = VALUES(last_duration_ms), last_run_at = VALUES(last_run_at)`),
		sessionID, rounds, toolCalls, toolErrors, prompt, completion, total, durationMs, ts,
	); err != nil {
		return err
	}
	_, err := s.db.Exec(
		`INSERT INTO agent_runs(session_id, rounds, tool_calls, tool_errors, prompt_tokens, completion_tokens, total_tokens, duration_ms, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sessionID, rounds, toolCalls, toolErrors, prompt, completion, total, durationMs, ts,
	)
	return err
}

// AgentRun is one executed agent turn for history charts.
type AgentRun struct {
	ID               int64  `json:"id"`
	SessionID        int64  `json:"session_id"`
	Rounds           int    `json:"rounds"`
	ToolCalls        int    `json:"tool_calls"`
	ToolErrors       int    `json:"tool_errors"`
	PromptTokens     int64  `json:"prompt_tokens"`
	CompletionTokens int64  `json:"completion_tokens"`
	TotalTokens      int64  `json:"total_tokens"`
	DurationMs       int64  `json:"duration_ms"`
	CreatedAt        string `json:"created_at"`
}

// GetAgentRuns returns the session's recent runs, newest first.
func (s *Store) GetAgentRuns(sessionID int64, limit int) ([]AgentRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, session_id, rounds, tool_calls, tool_errors, prompt_tokens, completion_tokens, total_tokens, duration_ms, created_at
		 FROM agent_runs WHERE session_id = ? ORDER BY id DESC LIMIT ?`, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentRun{}
	for rows.Next() {
		var r AgentRun
		if err := rows.Scan(&r.ID, &r.SessionID, &r.Rounds, &r.ToolCalls, &r.ToolErrors,
			&r.PromptTokens, &r.CompletionTokens, &r.TotalTokens, &r.DurationMs, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetAgentMetrics returns one session's totals (zero values when absent).
func (s *Store) GetAgentMetrics(sessionID int64) (AgentMetrics, error) {
	var m AgentMetrics
	m.SessionID = sessionID
	err := s.db.QueryRow(
		`SELECT runs, rounds, tool_calls, tool_errors, prompt_tokens, completion_tokens, total_tokens, last_duration_ms, last_run_at
		 FROM agent_metrics WHERE session_id = ?`, sessionID).
		Scan(&m.Runs, &m.Rounds, &m.ToolCalls, &m.ToolErrors, &m.PromptTokens, &m.CompletionTokens, &m.TotalTokens, &m.LastDurationMs, &m.LastRunAt)
	return m, err
}

// AgentGlobalMetrics aggregates agent usage across every conversation.
type AgentGlobalMetrics struct {
	Sessions         int64 `json:"sessions"`
	Runs             int64 `json:"runs"`
	Rounds           int64 `json:"rounds"`
	ToolCalls        int64 `json:"tool_calls"`
	ToolErrors       int64 `json:"tool_errors"`
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

func (s *Store) AgentMetricsTotals() (AgentGlobalMetrics, error) {
	var m AgentGlobalMetrics
	err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(runs),0), COALESCE(SUM(rounds),0), COALESCE(SUM(tool_calls),0),
		COALESCE(SUM(tool_errors),0), COALESCE(SUM(prompt_tokens),0), COALESCE(SUM(completion_tokens),0), COALESCE(SUM(total_tokens),0)
		FROM agent_metrics`).Scan(&m.Sessions, &m.Runs, &m.Rounds, &m.ToolCalls, &m.ToolErrors,
		&m.PromptTokens, &m.CompletionTokens, &m.TotalTokens)
	return m, err
}

// AgentSessionMetric is one conversation's usage row for the global dashboard.
type AgentSessionMetric struct {
	SessionID   int64  `json:"session_id"`
	Title       string `json:"title"`
	Runs        int64  `json:"runs"`
	ToolCalls   int64  `json:"tool_calls"`
	ToolErrors  int64  `json:"tool_errors"`
	TotalTokens int64  `json:"total_tokens"`
	LastRunAt   string `json:"last_run_at"`
}

func (s *Store) ListAgentSessionMetrics(limit int) ([]AgentSessionMetric, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT m.session_id, COALESCE(s.title,''), m.runs, m.tool_calls, m.tool_errors, m.total_tokens, m.last_run_at
		FROM agent_metrics m LEFT JOIN chat_sessions s ON s.id = m.session_id
		ORDER BY m.total_tokens DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentSessionMetric{}
	for rows.Next() {
		var r AgentSessionMetric
		if err := rows.Scan(&r.SessionID, &r.Title, &r.Runs, &r.ToolCalls, &r.ToolErrors, &r.TotalTokens, &r.LastRunAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
