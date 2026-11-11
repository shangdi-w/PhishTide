package store

// Long-running console agent jobs. A job is a self-contained prompt that the
// worker runs with the same tool set as an interactive turn, but detached from
// the HTTP connection, so closing the page does not kill it.

// AgentJob is one queued or finished background task.
type AgentJob struct {
	ID        int64  `json:"id"`
	SessionID int64  `json:"session_id"`
	Prompt    string `json:"prompt"`
	Status    string `json:"status"` // queued | running | done | error | canceled | awaiting
	Result    string `json:"result"`
	Error     string `json:"error"`
	Attempts  int    `json:"attempts"`
	Resumed   int    `json:"resumed"`
	RunAt     string `json:"run_at"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

const agentJobCols = `id, session_id, prompt, status, result, error, attempts, resumed, run_at, created_at, updated_at`

func (s *Store) CreateAgentJob(sessionID int64, prompt, runAt string) (int64, error) {
	ts := now()
	res, err := s.db.Exec(
		`INSERT INTO agent_jobs(session_id, prompt, status, result, error, attempts, run_at, created_at, updated_at) VALUES(?, ?, 'queued', '', '', 0, ?, ?, ?)`,
		sessionID, prompt, runAt, ts, ts,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateAgentJobStatus(id int64, status, result, errText string) error {
	_, err := s.db.Exec(
		`UPDATE agent_jobs SET status = ?, result = ?, error = ?, updated_at = ? WHERE id = ?`,
		status, result, errText, now(), id,
	)
	return err
}

func (s *Store) UpdateAgentJobAttempts(id int64, attempts int) error {
	_, err := s.db.Exec(`UPDATE agent_jobs SET attempts = ?, updated_at = ? WHERE id = ?`, attempts, now(), id)
	return err
}

// MarkAgentJobResumed records that the next run continues from the transcript
// instead of re-inserting the original prompt.
func (s *Store) MarkAgentJobResumed(id int64) error {
	_, err := s.db.Exec(`UPDATE agent_jobs SET resumed = 1, updated_at = ? WHERE id = ?`, now(), id)
	return err
}

// LatestAwaitingAgentJob returns the newest job parked on a confirmation.
func (s *Store) LatestAwaitingAgentJob(sessionID int64) (AgentJob, bool, error) {
	var j AgentJob
	err := s.db.QueryRow(`SELECT `+agentJobCols+` FROM agent_jobs WHERE session_id = ? AND status = 'awaiting' ORDER BY id DESC LIMIT 1`, sessionID).
		Scan(&j.ID, &j.SessionID, &j.Prompt, &j.Status, &j.Result, &j.Error, &j.Attempts, &j.Resumed, &j.RunAt, &j.CreatedAt, &j.UpdatedAt)
	if err != nil {
		return j, false, err
	}
	return j, true, nil
}

func (s *Store) GetAgentJob(id int64) (AgentJob, error) {
	var j AgentJob
	err := s.db.QueryRow(`SELECT `+agentJobCols+` FROM agent_jobs WHERE id = ?`, id).
		Scan(&j.ID, &j.SessionID, &j.Prompt, &j.Status, &j.Result, &j.Error, &j.Attempts, &j.Resumed, &j.RunAt, &j.CreatedAt, &j.UpdatedAt)
	return j, err
}

// ListAgentJobs returns recent jobs, newest first.
func (s *Store) ListAgentJobs(limit int) ([]AgentJob, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT `+agentJobCols+` FROM agent_jobs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	return scanAgentJobs(rows)
}

// ListActiveAgentJobs returns jobs that should be considered on startup.
func (s *Store) ListActiveAgentJobs() ([]AgentJob, error) {
	rows, err := s.db.Query(`SELECT ` + agentJobCols + ` FROM agent_jobs WHERE status IN ('queued','running') ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return scanAgentJobs(rows)
}

// ListAwaitingAgentJobs returns jobs parked on a confirmation.
func (s *Store) ListAwaitingAgentJobs() ([]AgentJob, error) {
	rows, err := s.db.Query(`SELECT ` + agentJobCols + ` FROM agent_jobs WHERE status = 'awaiting' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return scanAgentJobs(rows)
}

// ListDueAgentJobs returns queued jobs whose run_at has arrived (empty run_at
// means immediate).
func (s *Store) ListDueAgentJobs(nowStr string) ([]AgentJob, error) {
	rows, err := s.db.Query(
		`SELECT `+agentJobCols+` FROM agent_jobs WHERE status = 'queued' AND (run_at = '' OR run_at <= ?) ORDER BY id`, nowStr)
	if err != nil {
		return nil, err
	}
	return scanAgentJobs(rows)
}

func scanAgentJobs(rows interface {
	Next() bool
	Scan(...any) error
	Close() error
	Err() error
}) ([]AgentJob, error) {
	defer rows.Close()
	out := []AgentJob{}
	for rows.Next() {
		var j AgentJob
		if err := rows.Scan(&j.ID, &j.SessionID, &j.Prompt, &j.Status, &j.Result, &j.Error,
			&j.Attempts, &j.Resumed, &j.RunAt, &j.CreatedAt, &j.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// CancelAgentJob stops a queued, awaiting or running job.
func (s *Store) CancelAgentJob(id int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE agent_jobs SET status = 'canceled', updated_at = ? WHERE id = ? AND status IN ('queued','awaiting','running')`, now(), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RetryAgentJob requeues a failed or canceled job, resuming from its transcript.
func (s *Store) RetryAgentJob(id int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE agent_jobs SET status = 'queued', resumed = 1, error = '', updated_at = ? WHERE id = ? AND status IN ('error','canceled')`, now(), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
