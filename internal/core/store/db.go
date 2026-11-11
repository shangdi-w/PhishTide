package store

import (
	"database/sql"
	_ "embed"
	"fmt"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

//go:embed seed_mysql.sql
var seedMySQL string

// dialect selects the SQL dialect for the active database.
type dialect int

const (
	dialectSQLite dialect = iota
	dialectMySQL
)

// mysqlSchema is the MySQL DDL. It is split on ";" and executed statement by
// statement because the MySQL driver does not allow multi-statement Exec
// without multiStatements=true. The table is named target_groups because
// "groups" is a reserved word in MySQL 8.0.
const mysqlSchema = `
CREATE TABLE IF NOT EXISTS sending_profiles (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(255) NOT NULL UNIQUE,
	interface_type VARCHAR(16) NOT NULL DEFAULT 'SMTP',
	host VARCHAR(255) NOT NULL DEFAULT '',
	port INT NOT NULL DEFAULT 587,
	username VARCHAR(255) NOT NULL DEFAULT '',
	password TEXT NOT NULL,
	tls_mode VARCHAR(16) NOT NULL DEFAULT 'starttls',
	ignore_cert INT NOT NULL DEFAULT 1,
	from_name VARCHAR(255) NOT NULL DEFAULT '',
	from_email VARCHAR(255) NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS email_templates (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(255) NOT NULL UNIQUE,
	subject TEXT NOT NULL,
	html LONGTEXT NOT NULL,
	text LONGTEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS template_default_pages (
	template_id BIGINT PRIMARY KEY,
	landing_page_id BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS landing_pages (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(255) NOT NULL UNIQUE,
	kind VARCHAR(16) NOT NULL DEFAULT 'template',
	source_url TEXT NOT NULL,
	body LONGTEXT NOT NULL,
	content_type VARCHAR(255) NOT NULL DEFAULT 'text/html; charset=utf-8',
	capture_credentials INT NOT NULL DEFAULT 1,
	capture_passwords INT NOT NULL DEFAULT 1,
	redirect_url TEXT NOT NULL,
	error_message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS page_assets (
	page_id BIGINT NOT NULL,
	path VARCHAR(512) NOT NULL,
	content_type VARCHAR(255) NOT NULL,
	body LONGBLOB NOT NULL,
	PRIMARY KEY (page_id, path)
);
CREATE TABLE IF NOT EXISTS target_groups (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(255) NOT NULL UNIQUE,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS targets (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	group_id BIGINT NOT NULL,
	email VARCHAR(255) NOT NULL,
	first_name VARCHAR(255) NOT NULL DEFAULT '',
	last_name VARCHAR(255) NOT NULL DEFAULT '',
	position VARCHAR(255) NOT NULL DEFAULT '',
	department VARCHAR(255) NOT NULL DEFAULT '',
	KEY idx_targets_group (group_id)
);
CREATE TABLE IF NOT EXISTS campaigns (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(255) NOT NULL,
	email_template_id BIGINT NOT NULL,
	landing_page_id BIGINT NOT NULL,
	sending_profile_id BIGINT NOT NULL DEFAULT 0,
	email_template_b_id BIGINT NOT NULL DEFAULT 0,
	ab_split INT NOT NULL DEFAULT 100,
	link_ttl_hours INT NOT NULL DEFAULT 0,
	link_once INT NOT NULL DEFAULT 0,
	ip_allow TEXT NOT NULL,
	ip_deny TEXT NOT NULL,
	seed_emails TEXT NOT NULL,
	status VARCHAR(32) NOT NULL DEFAULT 'created',
	created_at TEXT NOT NULL,
	launch_date TEXT NOT NULL,
	completed_date TEXT NOT NULL,
	deleted_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS campaign_groups (
	campaign_id BIGINT NOT NULL,
	group_id BIGINT NOT NULL,
	PRIMARY KEY (campaign_id, group_id)
);
CREATE TABLE IF NOT EXISTS results (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	campaign_id BIGINT NOT NULL,
	target_id BIGINT NOT NULL,
	rid VARCHAR(64) NOT NULL UNIQUE,
	variant VARCHAR(8) NOT NULL DEFAULT 'A',
	status VARCHAR(32) NOT NULL DEFAULT 'sending',
	sent INT NOT NULL DEFAULT 0,
	opened INT NOT NULL DEFAULT 0,
	clicked INT NOT NULL DEFAULT 0,
	submitted INT NOT NULL DEFAULT 0,
	reported INT NOT NULL DEFAULT 0,
	unsubscribed INT NOT NULL DEFAULT 0,
	sent_at TEXT NOT NULL,
	opened_at TEXT NOT NULL,
	clicked_at TEXT NOT NULL,
	submitted_at TEXT NOT NULL,
	reported_at TEXT NOT NULL,
	unsubscribed_at TEXT NOT NULL,
	ip VARCHAR(64) NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL,
	KEY idx_results_campaign (campaign_id)
);
CREATE TABLE IF NOT EXISTS send_failures (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	campaign_id BIGINT NOT NULL,
	result_id BIGINT NOT NULL DEFAULT 0,
	email VARCHAR(255) NOT NULL DEFAULT '',
	kind VARCHAR(32) NOT NULL DEFAULT 'unknown',
	error TEXT NOT NULL,
	attempts INT NOT NULL DEFAULT 1,
	created_at TEXT NOT NULL,
	KEY idx_send_failures_campaign (campaign_id, id)
);
CREATE TABLE IF NOT EXISTS suppressions (
	email VARCHAR(255) PRIMARY KEY,
	reason VARCHAR(32) NOT NULL DEFAULT 'manual',
	note TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS send_ledger (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	campaign_id BIGINT NOT NULL DEFAULT 0,
	campaign_name VARCHAR(255) NOT NULL DEFAULT '',
	template_id BIGINT NOT NULL DEFAULT 0,
	email VARCHAR(255) NOT NULL DEFAULT '',
	subject TEXT NOT NULL,
	from_email VARCHAR(255) NOT NULL DEFAULT '',
	variant VARCHAR(16) NOT NULL DEFAULT '',
	status VARCHAR(16) NOT NULL DEFAULT 'sent',
	failure_kind VARCHAR(32) NOT NULL DEFAULT '',
	detail TEXT NOT NULL,
	message_id VARCHAR(255) NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	KEY idx_sl_campaign (campaign_id),
	KEY idx_sl_email (email)
);
CREATE TABLE IF NOT EXISTS deleted_campaigns (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	campaign_id BIGINT NOT NULL,
	name VARCHAR(255) NOT NULL,
	targets INT NOT NULL DEFAULT 0,
	sent INT NOT NULL DEFAULT 0,
	deleted_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bounces (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	campaign_id BIGINT NOT NULL,
	result_id BIGINT NOT NULL DEFAULT 0,
	email VARCHAR(255) NOT NULL DEFAULT '',
	kind VARCHAR(16) NOT NULL DEFAULT 'soft',
	action VARCHAR(16) NOT NULL DEFAULT '',
	status VARCHAR(16) NOT NULL DEFAULT '',
	diagnostic TEXT NOT NULL,
	created_at TEXT NOT NULL,
	KEY idx_bounces_campaign (campaign_id, id)
);
CREATE TABLE IF NOT EXISTS events (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	campaign_id BIGINT NOT NULL,
	target_id BIGINT NOT NULL,
	kind VARCHAR(32) NOT NULL,
	ip VARCHAR(64) NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL,
	referer TEXT NOT NULL,
	detail TEXT NOT NULL,
	ts TEXT NOT NULL,
	KEY idx_events_campaign (campaign_id)
);
CREATE TABLE IF NOT EXISTS submissions (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	campaign_id BIGINT NOT NULL,
	result_id BIGINT NOT NULL,
	ts TEXT NOT NULL,
	ip VARCHAR(64) NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL,
	referer TEXT NOT NULL,
	username VARCHAR(255) NOT NULL DEFAULT '',
	password VARCHAR(255) NOT NULL DEFAULT '',
	fields LONGTEXT NOT NULL,
	KEY idx_submissions_campaign (campaign_id)
);
CREATE TABLE IF NOT EXISTS llm_usage (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	model VARCHAR(64) NOT NULL,
	prompt_tokens INT NOT NULL DEFAULT 0,
	completion_tokens INT NOT NULL DEFAULT 0,
	total_tokens INT NOT NULL DEFAULT 0,
	ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS send_jobs (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	campaign_id BIGINT NOT NULL,
	status VARCHAR(16) NOT NULL DEFAULT 'pending',
	scheduled_at TEXT NOT NULL,
	batch_size INT NOT NULL DEFAULT 0,
	batch_delay_sec INT NOT NULL DEFAULT 0,
	sent INT NOT NULL DEFAULT 0,
	failed INT NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	started_at TEXT NOT NULL,
	completed_at TEXT NOT NULL,
	KEY idx_send_jobs_status (status)
);
CREATE TABLE IF NOT EXISTS app_settings (
	k VARCHAR(64) PRIMARY KEY,
	v LONGTEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS app_logs (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	ts VARCHAR(40) NOT NULL,
	level VARCHAR(16) NOT NULL,
	msg TEXT NOT NULL,
	attrs LONGTEXT NOT NULL,
	KEY idx_app_logs_ts (ts)
);
CREATE TABLE IF NOT EXISTS template_attachments (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	template_id BIGINT NOT NULL,
	name VARCHAR(255) NOT NULL,
	content_type VARCHAR(255) NOT NULL DEFAULT 'application/octet-stream',
	size_bytes BIGINT NOT NULL DEFAULT 0,
	body LONGBLOB NOT NULL,
	KEY idx_ta_template (template_id)
);
CREATE TABLE IF NOT EXISTS payload_attachments (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(255) NOT NULL,
	content_type VARCHAR(255) NOT NULL DEFAULT 'application/octet-stream',
	size_bytes BIGINT NOT NULL DEFAULT 0,
	sha256 VARCHAR(64) NOT NULL DEFAULT '',
	note TEXT NOT NULL,
	body LONGBLOB NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_sessions (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	title VARCHAR(255) NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_messages (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	session_id BIGINT NOT NULL,
	role VARCHAR(16) NOT NULL,
	content LONGTEXT NOT NULL,
	data LONGTEXT NOT NULL,
	created_at TEXT NOT NULL,
	KEY idx_cm_session (session_id)
);
CREATE TABLE IF NOT EXISTS chat_uploads (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	session_id BIGINT NOT NULL,
	name VARCHAR(255) NOT NULL,
	content_type VARCHAR(255) NOT NULL DEFAULT 'application/octet-stream',
	size_bytes BIGINT NOT NULL DEFAULT 0,
	body LONGBLOB NOT NULL,
	created_at TEXT NOT NULL,
	KEY idx_cu_session (session_id)
);
CREATE TABLE IF NOT EXISTS agent_todos (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	session_id BIGINT NOT NULL,
	text TEXT NOT NULL,
	status VARCHAR(16) NOT NULL DEFAULT 'pending',
	position INT NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL,
	KEY idx_at_session (session_id)
);
CREATE TABLE IF NOT EXISTS agent_jobs (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	session_id BIGINT NOT NULL DEFAULT 0,
	prompt LONGTEXT NOT NULL,
	status VARCHAR(16) NOT NULL DEFAULT 'queued',
	result LONGTEXT NOT NULL,
	error TEXT NOT NULL,
	attempts INT NOT NULL DEFAULT 0,
	resumed INT NOT NULL DEFAULT 0,
	run_at TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	KEY idx_aj_status (status)
);
CREATE TABLE IF NOT EXISTS agent_runs (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	session_id BIGINT NOT NULL,
	rounds INT NOT NULL DEFAULT 0,
	tool_calls INT NOT NULL DEFAULT 0,
	tool_errors INT NOT NULL DEFAULT 0,
	prompt_tokens BIGINT NOT NULL DEFAULT 0,
	completion_tokens BIGINT NOT NULL DEFAULT 0,
	total_tokens BIGINT NOT NULL DEFAULT 0,
	duration_ms BIGINT NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	KEY idx_ar_session (session_id, id)
);
CREATE TABLE IF NOT EXISTS agent_metrics (
	session_id BIGINT PRIMARY KEY,
	runs BIGINT NOT NULL DEFAULT 0,
	rounds BIGINT NOT NULL DEFAULT 0,
	tool_calls BIGINT NOT NULL DEFAULT 0,
	tool_errors BIGINT NOT NULL DEFAULT 0,
	prompt_tokens BIGINT NOT NULL DEFAULT 0,
	completion_tokens BIGINT NOT NULL DEFAULT 0,
	total_tokens BIGINT NOT NULL DEFAULT 0,
	last_duration_ms BIGINT NOT NULL DEFAULT 0,
	last_run_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS content_versions (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	kind VARCHAR(32) NOT NULL,
	object_id BIGINT NOT NULL,
	name VARCHAR(255) NOT NULL DEFAULT '',
	action VARCHAR(16) NOT NULL DEFAULT 'update',
	payload LONGTEXT NOT NULL,
	size_bytes INT NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	KEY idx_cv_object (kind, object_id)
);
CREATE TABLE IF NOT EXISTS agent_memories (
	mem_key VARCHAR(128) PRIMARY KEY,
	value LONGTEXT NOT NULL,
	category VARCHAR(16) NOT NULL DEFAULT 'fact',
	updated_at TEXT NOT NULL
);
`

// OpenMySQL opens a MySQL database with the given DSN and migrates the schema.
func OpenMySQL(dsn string) (*Store, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	for _, stmt := range splitSQL(mysqlSchema) {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("migrate mysql: %w", err)
		}
	}
	stmts := []string{
		`ALTER TABLE targets ADD COLUMN department VARCHAR(255) NOT NULL DEFAULT ''`,
		`ALTER TABLE campaigns ADD COLUMN email_template_b_id BIGINT NOT NULL DEFAULT 0`,
		`ALTER TABLE campaigns ADD COLUMN ab_split INT NOT NULL DEFAULT 100`,
		`ALTER TABLE campaigns ADD COLUMN link_ttl_hours INT NOT NULL DEFAULT 0`,
		`ALTER TABLE campaigns ADD COLUMN link_once INT NOT NULL DEFAULT 0`,
		`ALTER TABLE campaigns ADD COLUMN ip_allow TEXT NOT NULL`,
		`ALTER TABLE campaigns ADD COLUMN ip_deny TEXT NOT NULL`,
		`ALTER TABLE campaigns ADD COLUMN seed_emails TEXT NOT NULL`,
		`ALTER TABLE results ADD COLUMN variant VARCHAR(8) NOT NULL DEFAULT 'A'`,
		`ALTER TABLE landing_pages ADD COLUMN error_message TEXT NOT NULL`,
		`ALTER TABLE send_ledger ADD COLUMN message_id VARCHAR(255) NOT NULL DEFAULT ''`,
		`ALTER TABLE campaigns ADD COLUMN deleted_at TEXT NOT NULL`,
		`ALTER TABLE agent_jobs ADD COLUMN attempts INT NOT NULL DEFAULT 0`,
		`ALTER TABLE agent_jobs ADD COLUMN run_at TEXT NOT NULL`,
		`ALTER TABLE agent_memories ADD COLUMN category VARCHAR(16) NOT NULL DEFAULT 'fact'`,
		`ALTER TABLE agent_jobs ADD COLUMN resumed INT NOT NULL DEFAULT 0`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			db.Close()
			return nil, fmt.Errorf("migrate mysql: %w", err)
		}
	}
	st := &Store{db: db, d: dialectMySQL}
	if err := st.seedMySQL(); err != nil {
		db.Close()
		return nil, fmt.Errorf("seed mysql: %w", err)
	}
	return st, nil
}

// seedMySQL loads the built-in templates into MySQL. The seed uses INSERT IGNORE
// with fixed ids, so it is idempotent across restarts.
func (s *Store) seedMySQL() error {
	for _, stmt := range splitSQL(seedMySQL) {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// splitSQL splits a multi-statement SQL string on ";" while ignoring
// semicolons inside single-quoted string literals (e.g. DEFAULT
// 'text/html; charset=utf-8').
func splitSQL(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch r {
		case '\'':
			inQuote = !inQuote
			cur.WriteRune(r)
		case ';':
			cur.WriteRune(r)
			if !inQuote {
				if strings.TrimSpace(cur.String()) != "" {
					out = append(out, strings.TrimSpace(cur.String()))
				}
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

// sql picks the dialect-appropriate SQL statement.
func (s *Store) sql(sqliteSQL, mysqlSQL string) string {
	if s.d == dialectMySQL {
		return mysqlSQL
	}
	return sqliteSQL
}
