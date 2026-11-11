// Package store persists the phishing simulation platform's data in a single
// local SQLite database. The model follows GoPhish: reusable sending profiles,
// groups, email templates and landing pages, and a campaign that combines them
// with per-target results (tracked by a random id, or rid).
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"phishsim/internal/core/crypto"
)

// SendingProfile is a reusable SMTP configuration (GoPhish "sending profile").
type SendingProfile struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	InterfaceType string `json:"interface_type"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Username      string `json:"username"`
	Password      string `json:"password,omitempty"`
	TLSMode       string `json:"tls_mode"` // "none" | "starttls" | "ssl"
	IgnoreCert    bool   `json:"ignore_cert"`
	FromName      string `json:"from_name"`
	FromEmail     string `json:"from_email"`
}

// EmailTemplate is one phishing email template.
type EmailTemplate struct {
	ID                   int64  `json:"id"`
	Name                 string `json:"name"`
	Subject              string `json:"subject"`
	HTML                 string `json:"html"`
	Text                 string `json:"text"`
	DefaultLandingPageID int64  `json:"default_landing_page_id,omitempty"`
}

// LandingPage is a phishing landing page: a built-in template or a clone.
type LandingPage struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Kind               string `json:"kind"` // "template" | "clone" | "proxy"
	SourceURL          string `json:"source_url,omitempty"`
	Body               string `json:"-"`
	ContentType        string `json:"content_type"`
	CaptureCredentials bool   `json:"capture_credentials"`
	CapturePasswords   bool   `json:"capture_passwords"`
	RedirectURL        string `json:"redirect_url"`
	// ErrorMessage is the "wrong password" copy shown on a failed login. It
	// should match the page's language and brand; empty falls back to a
	// generic Chinese prompt.
	ErrorMessage string `json:"error_message"`
}

// PageAsset is one mirrored resource belonging to a cloned landing page.
type PageAsset struct {
	PageID      int64
	Path        string
	ContentType string
	Body        []byte
}

// Group is a reusable set of targets (GoPhish "group").
type Group struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	CreatedAt   string `json:"created_at"`
	TargetCount int    `json:"target_count"`
}

// Target is one recipient belonging to a group.
type Target struct {
	ID         int64  `json:"id"`
	GroupID    int64  `json:"group_id"`
	Email      string `json:"email"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	Position   string `json:"position"`
	Department string `json:"department"`
}

// Campaign combines one email template, one landing page, one sending profile,
// and one or more groups.
type Campaign struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	EmailTemplateID  int64  `json:"email_template_id"`
	LandingPageID    int64  `json:"landing_page_id"`
	SendingProfileID int64  `json:"sending_profile_id"`
	EmailTemplateBID int64  `json:"email_template_b_id"`
	ABSplit          int    `json:"ab_split"`
	LinkTTLHours     int    `json:"link_ttl_hours"`
	LinkOnce         bool   `json:"link_once"`
	IPAllow          string `json:"ip_allow"`
	IPDeny           string `json:"ip_deny"`
	SeedEmails       string `json:"seed_emails"`
	Status           string `json:"status"`
	CreatedAt        string `json:"created_at"`
	LaunchDate       string `json:"launch_date"`
	CompletedDate    string `json:"completed_date"`
	DeletedAt        string `json:"deleted_at,omitempty"`

	// Derived counts filled in by List/Get.
	Targets   int `json:"targets"`
	Sent      int `json:"sent"`
	Opened    int `json:"opened"`
	Clicked   int `json:"clicked"`
	Submitted int `json:"submitted"`
	Reported  int `json:"reported"`
}

// Result is one per-target tracking record (GoPhish "result"), keyed by rid.
type Result struct {
	ID             int64  `json:"id"`
	CampaignID     int64  `json:"campaign_id"`
	TargetID       int64  `json:"target_id"`
	Rid            string `json:"rid"`
	Status         string `json:"status"`
	Sent           bool   `json:"sent"`
	Opened         bool   `json:"opened"`
	Clicked        bool   `json:"clicked"`
	Submitted      bool   `json:"submitted"`
	Reported       bool   `json:"reported"`
	Unsubscribed   bool   `json:"unsubscribed"`
	SentAt         string `json:"sent_at,omitempty"`
	OpenedAt       string `json:"opened_at,omitempty"`
	ClickedAt      string `json:"clicked_at,omitempty"`
	SubmittedAt    string `json:"submitted_at,omitempty"`
	ReportedAt     string `json:"reported_at,omitempty"`
	UnsubscribedAt string `json:"unsubscribed_at,omitempty"`
	Variant        string `json:"variant,omitempty"`
	IP             string `json:"ip,omitempty"`
	UserAgent      string `json:"user_agent,omitempty"`

	// Joined target fields.
	Email      string `json:"email"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	Position   string `json:"position"`
	Department string `json:"department"`
}

// Submission is one captured form submission, retaining every submitted field.
type Submission struct {
	ID         int64               `json:"id"`
	CampaignID int64               `json:"campaign_id"`
	ResultID   int64               `json:"result_id"`
	TS         string              `json:"ts"`
	IP         string              `json:"ip"`
	UserAgent  string              `json:"user_agent"`
	Referer    string              `json:"referer,omitempty"`
	Username   string              `json:"username"`
	Password   string              `json:"password"`
	Fields     map[string][]string `json:"fields"`

	// Joined target fields.
	Email string `json:"email"`

	// Country/Org are filled in by the web layer from the optional offline
	// GeoIP database; they are not stored.
	Country string `json:"country,omitempty"`
	Org     string `json:"org,omitempty"`
}

// Event is a timeline event (sent / opened / clicked / submitted / reported,
// plus behavior events: page_load / dwell / page_click / field_focus /
// submit_attempt).
type Event struct {
	ID         int64  `json:"id"`
	CampaignID int64  `json:"campaign_id"`
	TargetID   int64  `json:"target_id"`
	Kind       string `json:"kind"`
	IP         string `json:"ip"`
	UserAgent  string `json:"user_agent"`
	Referer    string `json:"referer,omitempty"`
	Detail     string `json:"detail,omitempty"`
	TS         string `json:"ts"`
}

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS sending_profiles (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	interface_type TEXT NOT NULL DEFAULT 'SMTP',
	host TEXT NOT NULL DEFAULT '',
	port INTEGER NOT NULL DEFAULT 587,
	username TEXT NOT NULL DEFAULT '',
	password TEXT NOT NULL DEFAULT '',
	tls_mode TEXT NOT NULL DEFAULT 'starttls',
	ignore_cert INTEGER NOT NULL DEFAULT 1,
	from_name TEXT NOT NULL DEFAULT '',
	from_email TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS email_templates (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	subject TEXT NOT NULL,
	html TEXT NOT NULL,
	text TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS template_default_pages (
	template_id INTEGER PRIMARY KEY,
	landing_page_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS landing_pages (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	kind TEXT NOT NULL DEFAULT 'template',
	source_url TEXT NOT NULL DEFAULT '',
	body TEXT NOT NULL,
	content_type TEXT NOT NULL DEFAULT 'text/html; charset=utf-8',
	capture_credentials INTEGER NOT NULL DEFAULT 1,
	capture_passwords INTEGER NOT NULL DEFAULT 1,
	redirect_url TEXT NOT NULL DEFAULT '',
	error_message TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS page_assets (
	page_id INTEGER NOT NULL,
	path TEXT NOT NULL,
	content_type TEXT NOT NULL,
	body BLOB NOT NULL,
	PRIMARY KEY (page_id, path)
);
CREATE TABLE IF NOT EXISTS target_groups (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS targets (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	group_id INTEGER NOT NULL,
	email TEXT NOT NULL,
	first_name TEXT NOT NULL DEFAULT '',
	last_name TEXT NOT NULL DEFAULT '',
	position TEXT NOT NULL DEFAULT '',
	department TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS campaigns (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	email_template_id INTEGER NOT NULL,
	landing_page_id INTEGER NOT NULL,
	sending_profile_id INTEGER NOT NULL DEFAULT 0,
	email_template_b_id INTEGER NOT NULL DEFAULT 0,
	ab_split INTEGER NOT NULL DEFAULT 100,
	link_ttl_hours INTEGER NOT NULL DEFAULT 0,
	link_once INTEGER NOT NULL DEFAULT 0,
	ip_allow TEXT NOT NULL DEFAULT '',
	ip_deny TEXT NOT NULL DEFAULT '',
	seed_emails TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'created',
	created_at TEXT NOT NULL,
	launch_date TEXT NOT NULL DEFAULT '',
	completed_date TEXT NOT NULL DEFAULT '',
	deleted_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS campaign_groups (
	campaign_id INTEGER NOT NULL,
	group_id INTEGER NOT NULL,
	PRIMARY KEY (campaign_id, group_id)
);
CREATE TABLE IF NOT EXISTS results (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	campaign_id INTEGER NOT NULL,
	target_id INTEGER NOT NULL,
	rid TEXT NOT NULL UNIQUE,
	variant TEXT NOT NULL DEFAULT 'A',
	status TEXT NOT NULL DEFAULT 'sending',
	sent INTEGER NOT NULL DEFAULT 0,
	opened INTEGER NOT NULL DEFAULT 0,
	clicked INTEGER NOT NULL DEFAULT 0,
	submitted INTEGER NOT NULL DEFAULT 0,
	reported INTEGER NOT NULL DEFAULT 0,
	unsubscribed INTEGER NOT NULL DEFAULT 0,
	sent_at TEXT NOT NULL DEFAULT '',
	opened_at TEXT NOT NULL DEFAULT '',
	clicked_at TEXT NOT NULL DEFAULT '',
	submitted_at TEXT NOT NULL DEFAULT '',
	reported_at TEXT NOT NULL DEFAULT '',
	unsubscribed_at TEXT NOT NULL DEFAULT '',
	ip TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS send_failures (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	campaign_id INTEGER NOT NULL,
	result_id INTEGER NOT NULL DEFAULT 0,
	email TEXT NOT NULL DEFAULT '',
	kind TEXT NOT NULL DEFAULT 'unknown',
	error TEXT NOT NULL DEFAULT '',
	attempts INTEGER NOT NULL DEFAULT 1,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_send_failures_campaign ON send_failures(campaign_id, id);
CREATE TABLE IF NOT EXISTS suppressions (
	email TEXT PRIMARY KEY,
	reason TEXT NOT NULL DEFAULT 'manual',
	note TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS send_ledger (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	campaign_id INTEGER NOT NULL DEFAULT 0,
	campaign_name TEXT NOT NULL DEFAULT '',
	template_id INTEGER NOT NULL DEFAULT 0,
	email TEXT NOT NULL DEFAULT '',
	subject TEXT NOT NULL DEFAULT '',
	from_email TEXT NOT NULL DEFAULT '',
	variant TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'sent',
	failure_kind TEXT NOT NULL DEFAULT '',
	detail TEXT NOT NULL DEFAULT '',
	message_id TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sl_campaign ON send_ledger(campaign_id);
CREATE INDEX IF NOT EXISTS idx_sl_email ON send_ledger(email);
CREATE TABLE IF NOT EXISTS deleted_campaigns (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	campaign_id INTEGER NOT NULL,
	name TEXT NOT NULL,
	targets INTEGER NOT NULL DEFAULT 0,
	sent INTEGER NOT NULL DEFAULT 0,
	deleted_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bounces (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	campaign_id INTEGER NOT NULL,
	result_id INTEGER NOT NULL DEFAULT 0,
	email TEXT NOT NULL DEFAULT '',
	kind TEXT NOT NULL DEFAULT 'soft',
	action TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT '',
	diagnostic TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bounces_campaign ON bounces(campaign_id, id);
CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	campaign_id INTEGER NOT NULL,
	target_id INTEGER NOT NULL,
	kind TEXT NOT NULL,
	ip TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	referer TEXT NOT NULL DEFAULT '',
	detail TEXT NOT NULL DEFAULT '',
	ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS submissions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	campaign_id INTEGER NOT NULL,
	result_id INTEGER NOT NULL,
	ts TEXT NOT NULL,
	ip TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	referer TEXT NOT NULL DEFAULT '',
	username TEXT NOT NULL DEFAULT '',
	password TEXT NOT NULL DEFAULT '',
	fields TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_targets_group ON targets(group_id);
CREATE INDEX IF NOT EXISTS idx_results_campaign ON results(campaign_id);
CREATE INDEX IF NOT EXISTS idx_events_campaign ON events(campaign_id);
CREATE INDEX IF NOT EXISTS idx_submissions_campaign ON submissions(campaign_id);
CREATE TABLE IF NOT EXISTS llm_usage (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	model TEXT NOT NULL,
	prompt_tokens INTEGER NOT NULL DEFAULT 0,
	completion_tokens INTEGER NOT NULL DEFAULT 0,
	total_tokens INTEGER NOT NULL DEFAULT 0,
	ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS send_jobs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	campaign_id INTEGER NOT NULL,
	status TEXT NOT NULL DEFAULT 'pending',
	scheduled_at TEXT NOT NULL,
	batch_size INTEGER NOT NULL DEFAULT 0,
	batch_delay_sec INTEGER NOT NULL DEFAULT 0,
	sent INTEGER NOT NULL DEFAULT 0,
	failed INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	started_at TEXT NOT NULL,
	completed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS app_settings (
	k TEXT PRIMARY KEY,
	v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS app_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL,
	level TEXT NOT NULL,
	msg TEXT NOT NULL,
	attrs TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_app_logs_ts ON app_logs(ts);
CREATE TABLE IF NOT EXISTS template_attachments (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	template_id INTEGER NOT NULL,
	name TEXT NOT NULL,
	content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
	size_bytes INTEGER NOT NULL DEFAULT 0,
	body BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ta_template ON template_attachments(template_id);
CREATE TABLE IF NOT EXISTS payload_attachments (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
	size_bytes INTEGER NOT NULL DEFAULT 0,
	sha256 TEXT NOT NULL DEFAULT '',
	note TEXT NOT NULL DEFAULT '',
	body BLOB NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_sessions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	title TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_messages (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id INTEGER NOT NULL,
	role TEXT NOT NULL,
	content TEXT NOT NULL DEFAULT '',
	data TEXT NOT NULL DEFAULT '{}',
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cm_session ON chat_messages(session_id);
CREATE TABLE IF NOT EXISTS chat_uploads (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id INTEGER NOT NULL,
	name TEXT NOT NULL,
	content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
	size_bytes INTEGER NOT NULL DEFAULT 0,
	body BLOB NOT NULL,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cu_session ON chat_uploads(session_id);
CREATE TABLE IF NOT EXISTS agent_todos (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id INTEGER NOT NULL,
	text TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'pending',
	position INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_at_session ON agent_todos(session_id);
CREATE TABLE IF NOT EXISTS agent_jobs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id INTEGER NOT NULL DEFAULT 0,
	prompt TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'queued',
	result TEXT NOT NULL DEFAULT '',
	error TEXT NOT NULL DEFAULT '',
	attempts INTEGER NOT NULL DEFAULT 0,
	resumed INTEGER NOT NULL DEFAULT 0,
	run_at TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aj_status ON agent_jobs(status);
CREATE TABLE IF NOT EXISTS agent_runs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id INTEGER NOT NULL,
	rounds INTEGER NOT NULL DEFAULT 0,
	tool_calls INTEGER NOT NULL DEFAULT 0,
	tool_errors INTEGER NOT NULL DEFAULT 0,
	prompt_tokens INTEGER NOT NULL DEFAULT 0,
	completion_tokens INTEGER NOT NULL DEFAULT 0,
	total_tokens INTEGER NOT NULL DEFAULT 0,
	duration_ms INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ar_session ON agent_runs(session_id, id);
CREATE TABLE IF NOT EXISTS agent_metrics (
	session_id INTEGER PRIMARY KEY,
	runs INTEGER NOT NULL DEFAULT 0,
	rounds INTEGER NOT NULL DEFAULT 0,
	tool_calls INTEGER NOT NULL DEFAULT 0,
	tool_errors INTEGER NOT NULL DEFAULT 0,
	prompt_tokens INTEGER NOT NULL DEFAULT 0,
	completion_tokens INTEGER NOT NULL DEFAULT 0,
	total_tokens INTEGER NOT NULL DEFAULT 0,
	last_duration_ms INTEGER NOT NULL DEFAULT 0,
	last_run_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS content_versions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	kind TEXT NOT NULL,
	object_id INTEGER NOT NULL,
	name TEXT NOT NULL DEFAULT '',
	action TEXT NOT NULL DEFAULT 'update',
	payload TEXT NOT NULL,
	size_bytes INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cv_object ON content_versions(kind, object_id);
CREATE TABLE IF NOT EXISTS agent_memories (
	mem_key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	category TEXT NOT NULL DEFAULT 'fact',
	updated_at TEXT NOT NULL
);
`

// Store wraps the SQLite database and all persistence methods.
type Store struct {
	db        *sql.DB
	d         dialect
	secretKey []byte // AES-256 key for encrypting SMTP credentials at rest
}

// SetSecretKey enables at-rest encryption of sensitive fields (SMTP
// credentials). Call it once at startup, before any profile is written.
func (s *Store) SetSecretKey(key []byte) { s.secretKey = key }

// Open opens (or creates) the SQLite database at path and brings the schema up
// to date.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(sqliteSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := migrateSQLite(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db, d: dialectSQLite}, nil
}

// migrateSQLite adds columns introduced after the first schema release.
// SQLite has no "ADD COLUMN IF NOT EXISTS", so a duplicate-column error is the
// expected outcome once the column exists.
func migrateSQLite(db *sql.DB) error {
	stmts := []string{
		`ALTER TABLE targets ADD COLUMN department TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE campaigns ADD COLUMN email_template_b_id INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE campaigns ADD COLUMN ab_split INTEGER NOT NULL DEFAULT 100`,
		`ALTER TABLE campaigns ADD COLUMN link_ttl_hours INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE campaigns ADD COLUMN link_once INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE campaigns ADD COLUMN ip_allow TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE campaigns ADD COLUMN ip_deny TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE campaigns ADD COLUMN seed_emails TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE results ADD COLUMN variant TEXT NOT NULL DEFAULT 'A'`,
		`ALTER TABLE landing_pages ADD COLUMN error_message TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE send_ledger ADD COLUMN message_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE campaigns ADD COLUMN deleted_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE agent_jobs ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE agent_jobs ADD COLUMN run_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE agent_memories ADD COLUMN category TEXT NOT NULL DEFAULT 'fact'`,
		`ALTER TABLE agent_jobs ADD COLUMN resumed INTEGER NOT NULL DEFAULT 0`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return err
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// ---------------------------------------------------------------------------
// Sending profiles

// ListSendingProfiles returns every sending profile ordered by id.
func (s *Store) ListSendingProfiles() ([]SendingProfile, error) {
	rows, err := s.db.Query(`SELECT id, name, interface_type, host, port, username, password, tls_mode, ignore_cert, from_name, from_email FROM sending_profiles ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SendingProfile{}
	for rows.Next() {
		var p SendingProfile
		var ignore int
		if err := rows.Scan(&p.ID, &p.Name, &p.InterfaceType, &p.Host, &p.Port, &p.Username, &p.Password, &p.TLSMode, &ignore, &p.FromName, &p.FromEmail); err != nil {
			return nil, err
		}
		p.IgnoreCert = ignore != 0
		// Never ship SMTP credentials back to the console. The password is
		// decrypted on demand by GetSendingProfile when a campaign is sent.
		p.Password = ""
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetSendingProfile returns one sending profile by id.
func (s *Store) GetSendingProfile(id int64) (SendingProfile, error) {
	var p SendingProfile
	var ignore int
	err := s.db.QueryRow(`SELECT id, name, interface_type, host, port, username, password, tls_mode, ignore_cert, from_name, from_email FROM sending_profiles WHERE id = ?`, id).
		Scan(&p.ID, &p.Name, &p.InterfaceType, &p.Host, &p.Port, &p.Username, &p.Password, &p.TLSMode, &ignore, &p.FromName, &p.FromEmail)
	p.IgnoreCert = ignore != 0
	p.Password = s.decryptPw(p.Password)
	return p, err
}

// UpsertSendingProfile inserts or updates a sending profile by name.
func (s *Store) UpsertSendingProfile(p SendingProfile) (int64, error) {
	if p.Name == "" {
		return 0, errors.New("sending profile name required")
	}
	if p.TLSMode == "" {
		p.TLSMode = "starttls"
	}
	ignore := 0
	if p.IgnoreCert {
		ignore = 1
	}
	encPass, err := s.encryptPw(p.Password)
	if err != nil {
		return 0, err
	}
	// Editing an existing profile updates by id so the name can be corrected
	// without creating a duplicate row.
	if p.ID > 0 {
		res, err := s.db.Exec(`UPDATE sending_profiles SET name = ?, interface_type = ?, host = ?, port = ?,
			username = ?, password = ?, tls_mode = ?, ignore_cert = ?, from_name = ?, from_email = ?
			WHERE id = ?`,
			p.Name, p.InterfaceType, p.Host, p.Port, p.Username, encPass, p.TLSMode, ignore, p.FromName, p.FromEmail, p.ID)
		if err != nil {
			return 0, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return 0, errors.New("sending profile not found")
		}
		return p.ID, nil
	}
	res, err := s.db.Exec(s.sql(`
		INSERT INTO sending_profiles(name, interface_type, host, port, username, password, tls_mode, ignore_cert, from_name, from_email)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET interface_type=excluded.interface_type, host=excluded.host, port=excluded.port,
			username=excluded.username, password=excluded.password, tls_mode=excluded.tls_mode, ignore_cert=excluded.ignore_cert,
			from_name=excluded.from_name, from_email=excluded.from_email`,
		`INSERT INTO sending_profiles(name, interface_type, host, port, username, password, tls_mode, ignore_cert, from_name, from_email)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE interface_type=VALUES(interface_type), host=VALUES(host), port=VALUES(port),
			username=VALUES(username), password=VALUES(password), tls_mode=VALUES(tls_mode), ignore_cert=VALUES(ignore_cert),
			from_name=VALUES(from_name), from_email=VALUES(from_email)`),
		p.Name, p.InterfaceType, p.Host, p.Port, p.Username, encPass, p.TLSMode, ignore, p.FromName, p.FromEmail)
	if err != nil {
		return 0, err
	}
	if id, err := res.LastInsertId(); err == nil && id > 0 {
		return id, nil
	}
	var id int64
	if err := s.db.QueryRow(`SELECT id FROM sending_profiles WHERE name = ?`, p.Name).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// encryptPw encrypts a profile password for at-rest storage.
func (s *Store) encryptPw(plain string) (string, error) {
	if len(s.secretKey) == 0 {
		return plain, nil
	}
	return crypto.Encrypt(plain, s.secretKey)
}

// decryptPw decrypts a stored password, falling back to the raw value for
// legacy plaintext rows or when no key is configured.
func (s *Store) decryptPw(enc string) string {
	if len(s.secretKey) == 0 {
		return enc
	}
	if p, err := crypto.Decrypt(enc, s.secretKey); err == nil {
		return p
	}
	return enc
}

// ---------------------------------------------------------------------------
// Email templates

// ListTemplates returns every email template ordered by id.
func (s *Store) ListTemplates() ([]EmailTemplate, error) {
	rows, err := s.db.Query(`SELECT id, name, subject, html, text FROM email_templates ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EmailTemplate{}
	for rows.Next() {
		var t EmailTemplate
		if err := rows.Scan(&t.ID, &t.Name, &t.Subject, &t.HTML, &t.Text); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if assoc, err := s.templateDefaultPages(); err == nil {
		for i := range out {
			out[i].DefaultLandingPageID = assoc[out[i].ID]
		}
	}
	return out, nil
}

// SetTemplateDefaultPage associates an email template with a landing page.
// pageID <= 0 clears the association.
func (s *Store) SetTemplateDefaultPage(templateID, pageID int64) error {
	if templateID <= 0 {
		return errors.New("template id required")
	}
	if _, err := s.db.Exec(`DELETE FROM template_default_pages WHERE template_id = ?`, templateID); err != nil {
		return err
	}
	if pageID <= 0 {
		return nil
	}
	_, err := s.db.Exec(`INSERT INTO template_default_pages(template_id, landing_page_id) VALUES (?, ?)`, templateID, pageID)
	return err
}

// TemplateDefaultPage returns the default landing page id for a template, or 0.
func (s *Store) TemplateDefaultPage(templateID int64) int64 {
	var pageID int64
	_ = s.db.QueryRow(`SELECT landing_page_id FROM template_default_pages WHERE template_id = ?`, templateID).Scan(&pageID)
	return pageID
}

func (s *Store) templateDefaultPages() (map[int64]int64, error) {
	rows, err := s.db.Query(`SELECT template_id, landing_page_id FROM template_default_pages`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int64{}
	for rows.Next() {
		var tid, pid int64
		if err := rows.Scan(&tid, &pid); err != nil {
			return nil, err
		}
		out[tid] = pid
	}
	return out, rows.Err()
}

// GetTemplate returns one email template by id.
func (s *Store) GetTemplate(id int64) (EmailTemplate, error) {
	var t EmailTemplate
	err := s.db.QueryRow(`SELECT id, name, subject, html, text FROM email_templates WHERE id = ?`, id).
		Scan(&t.ID, &t.Name, &t.Subject, &t.HTML, &t.Text)
	return t, err
}

// UpsertTemplate inserts or updates a template by name.
func (s *Store) UpsertTemplate(t EmailTemplate) (int64, error) {
	if t.Name == "" {
		return 0, errors.New("template name required")
	}
	var priorID int64
	_ = s.db.QueryRow(`SELECT id FROM email_templates WHERE name = ?`, t.Name).Scan(&priorID)
	res, err := s.db.Exec(s.sql(`
		INSERT INTO email_templates(name, subject, html, text) VALUES (?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET subject=excluded.subject, html=excluded.html, text=excluded.text`,
		`INSERT INTO email_templates(name, subject, html, text) VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE subject=VALUES(subject), html=VALUES(html), text=VALUES(text)`),
		t.Name, t.Subject, t.HTML, t.Text)
	if err != nil {
		return 0, err
	}
	// MySQL reports LastInsertId 0 for an ON DUPLICATE KEY UPDATE that changed an
	// existing row, so resolve the id by name in that case.
	id, ierr := res.LastInsertId()
	if ierr != nil || id == 0 {
		if err := s.db.QueryRow(`SELECT id FROM email_templates WHERE name = ?`, t.Name).Scan(&id); err != nil {
			return 0, err
		}
	}
	action := "create"
	if priorID > 0 {
		action = "update"
	}
	t.ID = id
	_ = s.addContentVersion(VersionEmailTemplate, id, t.Name, action, t)
	return id, nil
}

// ---------------------------------------------------------------------------
// Landing pages

// ListPages returns every landing page ordered by id.
func (s *Store) ListPages() ([]LandingPage, error) {
	rows, err := s.db.Query(`SELECT id, name, kind, source_url, content_type, capture_credentials, capture_passwords, redirect_url, error_message FROM landing_pages ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LandingPage{}
	for rows.Next() {
		var p LandingPage
		var cc, cp int
		if err := rows.Scan(&p.ID, &p.Name, &p.Kind, &p.SourceURL, &p.ContentType, &cc, &cp, &p.RedirectURL, &p.ErrorMessage); err != nil {
			return nil, err
		}
		p.CaptureCredentials = cc != 0
		p.CapturePasswords = cp != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPage returns one landing page (body and metadata) by id.
func (s *Store) GetPage(id int64) (LandingPage, error) {
	var p LandingPage
	var cc, cp int
	err := s.db.QueryRow(`SELECT id, name, kind, source_url, body, content_type, capture_credentials, capture_passwords, redirect_url, error_message FROM landing_pages WHERE id = ?`, id).
		Scan(&p.ID, &p.Name, &p.Kind, &p.SourceURL, &p.Body, &p.ContentType, &cc, &cp, &p.RedirectURL, &p.ErrorMessage)
	p.CaptureCredentials = cc != 0
	p.CapturePasswords = cp != 0
	return p, err
}

// UpsertPage inserts or updates a landing page by name, replacing its assets.
func (s *Store) UpsertPage(p LandingPage, assets []PageAsset) (int64, error) {
	if p.Name == "" {
		return 0, errors.New("page name required")
	}
	cc, cp := 1, 1
	if !p.CaptureCredentials {
		cc = 0
	}
	if !p.CapturePasswords {
		cp = 0
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var priorID int64
	_ = tx.QueryRow(`SELECT id FROM landing_pages WHERE name = ?`, p.Name).Scan(&priorID)
	if _, err := tx.Exec(s.sql(`
		INSERT INTO landing_pages(name, kind, source_url, body, content_type, capture_credentials, capture_passwords, redirect_url, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET kind=excluded.kind, source_url=excluded.source_url, body=excluded.body,
			content_type=excluded.content_type, capture_credentials=excluded.capture_credentials,
			capture_passwords=excluded.capture_passwords, redirect_url=excluded.redirect_url,
			error_message=excluded.error_message`,
		`INSERT INTO landing_pages(name, kind, source_url, body, content_type, capture_credentials, capture_passwords, redirect_url, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE kind=VALUES(kind), source_url=VALUES(source_url), body=VALUES(body),
			content_type=VALUES(content_type), capture_credentials=VALUES(capture_credentials),
			capture_passwords=VALUES(capture_passwords), redirect_url=VALUES(redirect_url),
			error_message=VALUES(error_message)`),
		p.Name, p.Kind, p.SourceURL, p.Body, p.ContentType, cc, cp, p.RedirectURL, p.ErrorMessage); err != nil {
		return 0, err
	}
	var id int64
	if err := tx.QueryRow(`SELECT id FROM landing_pages WHERE name = ?`, p.Name).Scan(&id); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM page_assets WHERE page_id = ?`, id); err != nil {
		return 0, err
	}
	for _, a := range assets {
		if _, err := tx.Exec(`INSERT INTO page_assets(page_id, path, content_type, body) VALUES (?, ?, ?, ?)`,
			id, a.Path, a.ContentType, a.Body); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	action := "create"
	if priorID > 0 {
		action = "update"
	}
	p.ID = id
	_ = s.addContentVersion(VersionLandingPage, id, p.Name, action, pageVersionPayload(p))
	return id, nil
}

// GetAsset returns one mirrored page asset by path.
func (s *Store) GetAsset(pageID int64, path string) (PageAsset, error) {
	var a PageAsset
	err := s.db.QueryRow(`SELECT page_id, path, content_type, body FROM page_assets WHERE page_id = ? AND path = ?`,
		pageID, path).Scan(&a.PageID, &a.Path, &a.ContentType, &a.Body)
	return a, err
}

// ---------------------------------------------------------------------------
// Groups

// ListGroups returns every group with its target count.
func (s *Store) ListGroups() ([]Group, error) {
	rows, err := s.db.Query(`SELECT id, name, created_at FROM target_groups ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		_ = s.db.QueryRow(`SELECT count(*) FROM targets WHERE group_id = ?`, out[i].ID).Scan(&out[i].TargetCount)
	}
	return out, nil
}

// GetGroup returns one group by id.
func (s *Store) GetGroup(id int64) (Group, error) {
	var g Group
	err := s.db.QueryRow(`SELECT id, name, created_at FROM target_groups WHERE id = ?`, id).Scan(&g.ID, &g.Name, &g.CreatedAt)
	if err != nil {
		return g, err
	}
	_ = s.db.QueryRow(`SELECT count(*) FROM targets WHERE group_id = ?`, id).Scan(&g.TargetCount)
	return g, nil
}

// CreateGroup inserts a new group.
func (s *Store) CreateGroup(name string) (int64, error) {
	if name == "" {
		return 0, errors.New("group name required")
	}
	res, err := s.db.Exec(`INSERT INTO target_groups(name, created_at) VALUES (?, ?)`, name, now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// AddTargetsToGroup inserts targets into a group.
func (s *Store) AddTargetsToGroup(groupID int64, targets []Target) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n := 0
	for _, t := range targets {
		email := strings.TrimSpace(t.Email)
		// Reject malformed addresses at the storage boundary: a CR/LF here
		// would otherwise reach the SMTP envelope and the To header.
		if !validTargetEmail(email) {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO targets(group_id, email, first_name, last_name, position, department) VALUES (?, ?, ?, ?, ?, ?)`,
			groupID, email, t.FirstName, t.LastName, t.Position, t.Department); err != nil {
			return 0, err
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// validTargetEmail is a deliberately small sanity check: one @, no whitespace
// or header/command separators, bounded length. It is not full RFC 5322.
func validTargetEmail(s string) bool {
	if s == "" || len(s) > 254 {
		return false
	}
	if strings.ContainsAny(s, " \t\r\n<>,;\"'") {
		return false
	}
	if strings.Count(s, "@") != 1 {
		return false
	}
	at := strings.IndexByte(s, '@')
	return at > 0 && at < len(s)-1
}

// DeleteCampaignResult removes one target's result from a campaign without
// touching the group. Already-sent or submitted targets are refused so
// evidence and statistics are not silently lost.
func (s *Store) DeleteCampaignResult(campaignID, resultID int64) error {
	var targetID int64
	var sent, submitted bool
	err := s.db.QueryRow(`SELECT target_id, sent, submitted FROM results WHERE id = ? AND campaign_id = ?`,
		resultID, campaignID).Scan(&targetID, &sent, &submitted)
	if err != nil {
		return errors.New("result not found")
	}
	if sent || submitted {
		return errors.New("该目标已发送或已提交，不能移除；请先终止活动")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM submissions WHERE result_id = ?`, resultID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM send_failures WHERE campaign_id = ? AND result_id = ?`, campaignID, resultID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM bounces WHERE campaign_id = ? AND result_id = ?`, campaignID, resultID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM events WHERE campaign_id = ? AND target_id = ?`, campaignID, targetID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM results WHERE id = ? AND campaign_id = ?`, resultID, campaignID); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteTarget removes one target from a group. Targets already used by a
// campaign are kept so historical results stay joinable.
func (s *Store) DeleteTarget(groupID, targetID int64) error {
	var used int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM results WHERE target_id = ?`, targetID).Scan(&used); err != nil {
		return err
	}
	if used > 0 {
		return errors.New("该目标已用于活动，不能删除；请先删除相关活动")
	}
	res, err := s.db.Exec(`DELETE FROM targets WHERE id = ? AND group_id = ?`, targetID, groupID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("target not found")
	}
	return nil
}

// ListGroupTargets returns the targets of a group.
func (s *Store) ListGroupTargets(groupID int64) ([]Target, error) {
	rows, err := s.db.Query(`SELECT id, group_id, email, first_name, last_name, position, department FROM targets WHERE group_id = ? ORDER BY id`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Target{}
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.ID, &t.GroupID, &t.Email, &t.FirstName, &t.LastName, &t.Position, &t.Department); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Campaigns

// CreateCampaign inserts a campaign, links the given groups, and materializes
// per-target results (deduplicated by email) with a fresh rid each.
func (s *Store) CreateCampaign(c Campaign, groupIDs []int64) (int64, error) {
	if c.Name == "" {
		return 0, errors.New("campaign name required")
	}
	if c.EmailTemplateID == 0 || c.LandingPageID == 0 {
		return 0, errors.New("campaign requires an email template and a landing page")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO campaigns(name, email_template_id, email_template_b_id, ab_split, landing_page_id, sending_profile_id, link_ttl_hours, link_once, ip_allow, ip_deny, seed_emails, status, created_at, launch_date, completed_date, deleted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'created', ?, '', '', '')`,
		c.Name, c.EmailTemplateID, c.EmailTemplateBID, c.ABSplit, c.LandingPageID, c.SendingProfileID,
		c.LinkTTLHours, c.LinkOnce, c.IPAllow, c.IPDeny, c.SeedEmails, now())
	if err != nil {
		return 0, err
	}
	campID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	seen := map[string]bool{}
	type pair struct {
		id    int64
		email string
	}
	for _, gid := range groupIDs {
		if _, err := tx.Exec(s.sql(`INSERT OR IGNORE INTO campaign_groups(campaign_id, group_id) VALUES (?, ?)`, `INSERT IGNORE INTO campaign_groups(campaign_id, group_id) VALUES (?, ?)`), campID, gid); err != nil {
			return 0, err
		}
		rows, err := tx.Query(`SELECT id, email FROM targets WHERE group_id = ?`, gid)
		if err != nil {
			return 0, err
		}
		// Drain the result set fully before issuing further statements on the
		// same transaction connection (MySQL forbids interleaving).
		var pairs []pair
		for rows.Next() {
			var p pair
			if err := rows.Scan(&p.id, &p.email); err != nil {
				rows.Close()
				return 0, err
			}
			pairs = append(pairs, p)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, err
		}
		for _, p := range pairs {
			key := strings.ToLower(strings.TrimSpace(p.email))
			if seen[key] {
				continue
			}
			seen[key] = true
			variant := "A"
			if c.EmailTemplateBID > 0 {
				split := c.ABSplit
				if split < 0 || split > 100 {
					split = 50
				}
				if mrand.IntN(100) >= split {
					variant = "B"
				}
			}
			if _, err := tx.Exec(`INSERT INTO results(campaign_id, target_id, rid, variant, status, sent, opened, clicked, submitted, reported, unsubscribed, sent_at, opened_at, clicked_at, submitted_at, reported_at, unsubscribed_at, ip, user_agent) VALUES (?, ?, ?, ?, 'sending', 0, 0, 0, 0, 0, 0, '', '', '', '', '', '', '', '')`,
				campID, p.id, newRid(), variant); err != nil {
				return 0, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return campID, nil
}

// GetCampaign returns one campaign with derived counts.
func (s *Store) GetCampaign(id int64) (Campaign, error) {
	var c Campaign
	err := s.db.QueryRow(`SELECT id, name, email_template_id, email_template_b_id, ab_split, landing_page_id, sending_profile_id, link_ttl_hours, link_once, ip_allow, ip_deny, seed_emails, status, created_at, launch_date, completed_date, deleted_at FROM campaigns WHERE id = ?`, id).
		Scan(&c.ID, &c.Name, &c.EmailTemplateID, &c.EmailTemplateBID, &c.ABSplit, &c.LandingPageID, &c.SendingProfileID,
			&c.LinkTTLHours, &c.LinkOnce, &c.IPAllow, &c.IPDeny, &c.SeedEmails, &c.Status, &c.CreatedAt, &c.LaunchDate, &c.CompletedDate, &c.DeletedAt)
	if err != nil {
		return c, err
	}
	s.fillCounts(&c)
	return c, nil
}

// ListCampaigns returns all campaigns with derived counts, newest first.
func (s *Store) ListCampaigns() ([]Campaign, error) {
	rows, err := s.db.Query(`SELECT id, name, email_template_id, email_template_b_id, ab_split, landing_page_id, sending_profile_id, link_ttl_hours, link_once, ip_allow, ip_deny, seed_emails, status, created_at, launch_date, completed_date FROM campaigns WHERE COALESCE(deleted_at,'') = '' ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Campaign{}
	for rows.Next() {
		var c Campaign
		if err := rows.Scan(&c.ID, &c.Name, &c.EmailTemplateID, &c.EmailTemplateBID, &c.ABSplit, &c.LandingPageID, &c.SendingProfileID,
			&c.LinkTTLHours, &c.LinkOnce, &c.IPAllow, &c.IPDeny, &c.SeedEmails, &c.Status, &c.CreatedAt, &c.LaunchDate, &c.CompletedDate); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		s.fillCounts(&out[i])
	}
	return out, nil
}

func (s *Store) fillCounts(c *Campaign) {
	_ = s.db.QueryRow(`SELECT count(*), coalesce(sum(sent),0), coalesce(sum(opened),0), coalesce(sum(clicked),0), coalesce(sum(submitted),0), coalesce(sum(reported),0) FROM results WHERE campaign_id = ?`, c.ID).
		Scan(&c.Targets, &c.Sent, &c.Opened, &c.Clicked, &c.Submitted, &c.Reported)
}

// ListResults returns per-target results for a campaign, joined with target
// identity.
func (s *Store) ListResults(campaignID int64) ([]Result, error) {
	rows, err := s.db.Query(`
		SELECT r.id, r.campaign_id, r.target_id, r.rid, r.variant, r.status, r.sent, r.opened, r.clicked, r.submitted, r.reported, r.unsubscribed,
		       r.sent_at, r.opened_at, r.clicked_at, r.submitted_at, r.reported_at, r.unsubscribed_at, r.ip, r.user_agent,
		       t.email, t.first_name, t.last_name, t.position, t.department
		FROM results r JOIN targets t ON t.id = r.target_id
		WHERE r.campaign_id = ? ORDER BY r.id`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Result{}
	for rows.Next() {
		var r Result
		if err := rows.Scan(&r.ID, &r.CampaignID, &r.TargetID, &r.Rid, &r.Variant, &r.Status,
			&r.Sent, &r.Opened, &r.Clicked, &r.Submitted, &r.Reported, &r.Unsubscribed,
			&r.SentAt, &r.OpenedAt, &r.ClickedAt, &r.SubmittedAt, &r.ReportedAt, &r.UnsubscribedAt,
			&r.IP, &r.UserAgent, &r.Email, &r.FirstName, &r.LastName, &r.Position, &r.Department); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ResultByRid returns the joined result + target identity for a tracking rid.
func (s *Store) ResultByRid(rid string) (Result, error) {
	var r Result
	err := s.db.QueryRow(`
		SELECT r.id, r.campaign_id, r.target_id, r.rid, r.variant, r.status, r.sent, r.opened, r.clicked, r.submitted, r.reported, r.unsubscribed,
		       r.sent_at, r.opened_at, r.clicked_at, r.submitted_at, r.reported_at, r.unsubscribed_at, r.ip, r.user_agent,
		       t.email, t.first_name, t.last_name, t.position, t.department
		FROM results r JOIN targets t ON t.id = r.target_id
		WHERE r.rid = ?`, rid).
		Scan(&r.ID, &r.CampaignID, &r.TargetID, &r.Rid, &r.Variant, &r.Status,
			&r.Sent, &r.Opened, &r.Clicked, &r.Submitted, &r.Reported, &r.Unsubscribed,
			&r.SentAt, &r.OpenedAt, &r.ClickedAt, &r.SubmittedAt, &r.ReportedAt, &r.UnsubscribedAt,
			&r.IP, &r.UserAgent, &r.Email, &r.FirstName, &r.LastName, &r.Position, &r.Department)
	return r, err
}

// MarkSent flags a result as emailed.
func (s *Store) MarkSent(resultID int64) {
	_, _ = s.db.Exec(`UPDATE results SET sent = 1, status = 'sent', sent_at = ? WHERE id = ? AND sent = 0`, now(), resultID)
}

// MarkOpened records the first open for a result.
func (s *Store) MarkOpened(r Result, ip, ua, referer string) {
	s.touch(r, "opened", ip, ua, referer)
}

// MarkClicked records the first click for a result.
func (s *Store) MarkClicked(r Result, ip, ua, referer string) {
	s.touch(r, "clicked", ip, ua, referer)
}

// MarkReported records that the target reported the phishing email.
func (s *Store) MarkReported(r Result, ip, ua, referer string) {
	s.touch(r, "reported", ip, ua, referer)
}

// Unsubscribe marks a result as unsubscribed by rid.
func (s *Store) Unsubscribe(rid string) error {
	_, err := s.db.Exec(`UPDATE results SET unsubscribed = 1, unsubscribed_at = ? WHERE rid = ?`, now(), rid)
	return err
}

func (s *Store) touch(r Result, kind, ip, ua, referer string) {
	col := map[string]string{"opened": "opened", "clicked": "clicked", "reported": "reported"}[kind]
	_, _ = s.db.Exec(fmt.Sprintf(`UPDATE results SET %s = 1, %s_at = ?, ip = ?, user_agent = ? WHERE id = ? AND %s = 0`,
		col, col, col), now(), ip, ua, r.ID)
	s.insertEvent(r.CampaignID, r.TargetID, kind, ip, ua, referer, "")
}

// CountSubmissions returns how many credential submissions a result has made.
// The landing flow uses it to decide whether to show the "wrong password"
// prompt again or to let the visitor through.
func (s *Store) CountSubmissions(resultID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM submissions WHERE result_id = ?`, resultID).Scan(&n)
	return n, err
}

// RecordSubmission stores a captured form submission and flags the result.
func (s *Store) RecordSubmission(r Result, ip, ua, referer, username, password string, fields map[string][]string) error {
	_, _ = s.db.Exec(`UPDATE results SET submitted = 1, status = 'submitted', submitted_at = ?, ip = ?, user_agent = ? WHERE id = ? AND submitted = 0`,
		now(), ip, ua, r.ID)
	s.insertEvent(r.CampaignID, r.TargetID, "submitted", ip, ua, referer, "")
	// The dedicated password column holds the captured secret; drop duplicate
	// password keys from the free-form field map so the plaintext is not
	// persisted twice.
	for k := range fields {
		switch strings.ToLower(k) {
		case "password", "pass", "pwd", "passwd":
			fields[k] = []string{""}
		}
	}
	raw, _ := json.Marshal(fields)
	_, err := s.db.Exec(`
		INSERT INTO submissions(campaign_id, result_id, ts, ip, user_agent, referer, username, password, fields)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.CampaignID, r.ID, now(), ip, ua, referer, username,
		s.encryptSecret(password), s.encryptSecret(string(raw)))
	return err
}

// encryptSecret seals a captured secret at rest when a key is configured.
// The prefix lets decryptSecret distinguish encrypted rows from legacy
// plaintext ones after an upgrade.
func (s *Store) encryptSecret(plain string) string {
	if plain == "" || len(s.secretKey) == 0 {
		return plain
	}
	enc, err := crypto.Encrypt(plain, s.secretKey)
	if err != nil {
		return plain
	}
	return "enc:v1:" + enc
}

func (s *Store) decryptSecret(v string) string {
	if !strings.HasPrefix(v, "enc:v1:") {
		return v
	}
	if len(s.secretKey) == 0 {
		return ""
	}
	plain, err := crypto.Decrypt(strings.TrimPrefix(v, "enc:v1:"), s.secretKey)
	if err != nil {
		return ""
	}
	return plain
}

// EncryptSetting seals a sensitive app_settings value (for example the LLM API
// key) at rest with the platform secret key.
func (s *Store) EncryptSetting(plain string) string { return s.encryptSecret(plain) }

// DecryptSetting opens a value sealed by EncryptSetting. Legacy plaintext
// values pass through unchanged.
func (s *Store) DecryptSetting(v string) string { return s.decryptSecret(v) }

// RecordBehavior appends one client-side behavior event (page_load, dwell,
// page_click, field_focus, submit_attempt) for a tracking rid.
func (s *Store) RecordBehavior(rid, kind, detail, ip, ua string) {
	r, err := s.ResultByRid(rid)
	if err != nil {
		return
	}
	s.insertEvent(r.CampaignID, r.TargetID, kind, ip, ua, "", detail)
}

func (s *Store) insertEvent(campaignID, targetID int64, kind, ip, ua, referer, detail string) {
	_, _ = s.db.Exec(`INSERT INTO events(campaign_id, target_id, kind, ip, user_agent, referer, detail, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		campaignID, targetID, kind, ip, ua, referer, detail, now())
}

// TerminateCampaign stops a campaign: its landing pages serve a neutral
// maintenance page instead of the phishing content.
func (s *Store) TerminateCampaign(id int64) error {
	_, err := s.db.Exec(`UPDATE campaigns SET status = 'terminated', completed_date = ? WHERE id = ?`, now(), id)
	return err
}

// RenameCampaign updates a campaign's display name.
func (s *Store) RenameCampaign(id int64, name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("campaign name required")
	}
	_, err := s.db.Exec(`UPDATE campaigns SET name = ? WHERE id = ?`, name, id)
	return err
}

// deleteCampaignsTx removes the given campaigns and every row that belongs to
// them (submissions, events, results, group links). The caller owns the
// transaction. Shared resources (targets, groups, pages, templates) are kept.
func deleteCampaignsTx(tx *sql.Tx, ids []int64) error {
	for _, id := range ids {
		for _, stmt := range []string{
			`DELETE FROM submissions WHERE campaign_id = ?`,
			`DELETE FROM send_failures WHERE campaign_id = ?`,
			`DELETE FROM bounces WHERE campaign_id = ?`,
			`DELETE FROM events WHERE campaign_id = ?`,
			`DELETE FROM results WHERE campaign_id = ?`,
			`DELETE FROM campaign_groups WHERE campaign_id = ?`,
			`DELETE FROM campaigns WHERE id = ?`,
		} {
			if _, err := tx.Exec(stmt, id); err != nil {
				return err
			}
		}
	}
	return nil
}

// queryIDs runs a single-column int64 SELECT and returns the values.
func (s *Store) queryIDs(query string, args ...any) ([]int64, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// DeleteCampaign removes a campaign and every row that belongs to it
// (submissions, events, results, and its group links). Targets, groups, pages,
// and templates are shared and left untouched.
// SoftDeleteCampaign moves a campaign to the recycle bin. Results,
// submissions, events, the send ledger and the deletion tombstone are kept.
func (s *Store) SoftDeleteCampaign(id int64) error {
	res, err := s.db.Exec(`UPDATE campaigns SET deleted_at = ? WHERE id = ? AND COALESCE(deleted_at,'') = ''`, now(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("活动不存在或已在回收站")
	}
	// Pending scheduled sends for a deleted campaign must not fire later.
	_, _ = s.db.Exec(`UPDATE send_jobs SET status = 'cancelled' WHERE campaign_id = ? AND status = 'pending'`, id)
	return nil
}

// RestoreCampaign brings a soft-deleted campaign back.
func (s *Store) RestoreCampaign(id int64) error {
	camp, err := s.GetCampaign(id)
	if err != nil {
		return errors.New("回收站里没有这个活动")
	}
	if camp.DeletedAt == "" {
		return errors.New("回收站里没有这个活动")
	}
	// Assets may have been deleted while the campaign sat in the recycle bin.
	missing := []string{}
	if _, err := s.GetTemplate(camp.EmailTemplateID); err != nil {
		missing = append(missing, "邮件模板")
	}
	if camp.EmailTemplateBID > 0 {
		if _, err := s.GetTemplate(camp.EmailTemplateBID); err != nil {
			missing = append(missing, "B 模板")
		}
	}
	if _, err := s.GetPage(camp.LandingPageID); err != nil {
		missing = append(missing, "落地页")
	}
	if camp.SendingProfileID > 0 {
		if _, err := s.GetSendingProfile(camp.SendingProfileID); err != nil {
			missing = append(missing, "发件账号")
		}
	}
	rows, gerr := s.db.Query(`SELECT group_id FROM campaign_groups WHERE campaign_id = ?`, id)
	if gerr == nil {
		var gids []int64
		for rows.Next() {
			var gid int64
			if rows.Scan(&gid) == nil {
				gids = append(gids, gid)
			}
		}
		rows.Close()
		for _, gid := range gids {
			if _, err := s.GetGroup(gid); err != nil {
				missing = append(missing, "目标组")
				break
			}
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("无法恢复：引用的%s已被删除，请先重建或改绑这些对象", strings.Join(missing, "、"))
	}
	res, err := s.db.Exec(`UPDATE campaigns SET deleted_at = '' WHERE id = ? AND COALESCE(deleted_at,'') != ''`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("回收站里没有这个活动")
	}
	return nil
}

// ListDeletedCampaigns returns recycle-bin campaigns with their counters.
func (s *Store) ListCampaignsInRecycleBin() ([]Campaign, error) {
	rows, err := s.db.Query(`SELECT id, name, email_template_id, email_template_b_id, ab_split, landing_page_id, sending_profile_id, link_ttl_hours, link_once, ip_allow, ip_deny, seed_emails, status, created_at, launch_date, completed_date, deleted_at FROM campaigns WHERE COALESCE(deleted_at,'') != '' ORDER BY deleted_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Campaign{}
	for rows.Next() {
		var c Campaign
		if err := rows.Scan(&c.ID, &c.Name, &c.EmailTemplateID, &c.EmailTemplateBID, &c.ABSplit, &c.LandingPageID, &c.SendingProfileID,
			&c.LinkTTLHours, &c.LinkOnce, &c.IPAllow, &c.IPDeny, &c.SeedEmails, &c.Status, &c.CreatedAt, &c.LaunchDate, &c.CompletedDate, &c.DeletedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		s.fillCounts(&out[i])
	}
	return out, nil
}

func (s *Store) DeleteCampaign(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := deleteCampaignsTx(tx, []int64{id}); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteSendingProfile removes a sending profile and detaches it from any
// campaign that referenced it, so the campaign falls back to "not bound".
func (s *Store) DeleteSendingProfile(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE campaigns SET sending_profile_id = 0 WHERE sending_profile_id = ?`, id); err != nil {
		return err
	}
	res, err := tx.Exec(`DELETE FROM sending_profiles WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("发件配置不存在")
	}
	return tx.Commit()
}

// RenameGroup updates a group's display name.
func (s *Store) RenameGroup(id int64, name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("group name required")
	}
	_, err := s.db.Exec(`UPDATE target_groups SET name = ? WHERE id = ?`, name, id)
	return err
}

// DeleteGroup removes a group, its targets, and every campaign row
// (results/submissions/events) that referenced those targets.
func (s *Store) DeleteGroup(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range []string{
		`DELETE FROM submissions WHERE result_id IN (SELECT r.id FROM results r JOIN targets t ON t.id = r.target_id WHERE t.group_id = ?)`,
		`DELETE FROM events WHERE target_id IN (SELECT id FROM targets WHERE group_id = ?)`,
		`DELETE FROM results WHERE target_id IN (SELECT id FROM targets WHERE group_id = ?)`,
		`DELETE FROM campaign_groups WHERE group_id = ?`,
		`DELETE FROM targets WHERE group_id = ?`,
		`DELETE FROM target_groups WHERE id = ?`,
	} {
		if _, err := tx.Exec(stmt, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RenamePage updates a landing page's display name.
func (s *Store) RenamePage(id int64, name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("page name required")
	}
	_, err := s.db.Exec(`UPDATE landing_pages SET name = ? WHERE id = ?`, name, id)
	return err
}

// DeletePage removes a landing page and its mirrored assets. Campaigns that
// reference the page are cascade-deleted too.
func (s *Store) DeletePage(id int64) error {
	ids, err := s.queryIDs(`SELECT id FROM campaigns WHERE landing_page_id = ?`, id)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := deleteCampaignsTx(tx, ids); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM page_assets WHERE page_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM content_versions WHERE kind = ? AND object_id = ?`, VersionLandingPage, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM landing_pages WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// RenameTemplate updates an email template's display name.
func (s *Store) RenameTemplate(id int64, name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("template name required")
	}
	_, err := s.db.Exec(`UPDATE email_templates SET name = ? WHERE id = ?`, name, id)
	return err
}

// DeleteTemplate removes an email template. Campaigns that reference the
// template are cascade-deleted too.
func (s *Store) DeleteTemplate(id int64) error {
	ids, err := s.queryIDs(`SELECT id FROM campaigns WHERE email_template_id = ?`, id)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := deleteCampaignsTx(tx, ids); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM content_versions WHERE kind = ? AND object_id = ?`, VersionEmailTemplate, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM email_templates WHERE id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM template_default_pages WHERE template_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM template_attachments WHERE template_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// SendJob is a queued or scheduled campaign send.
type SendJob struct {
	ID            int64  `json:"id"`
	CampaignID    int64  `json:"campaign_id"`
	Status        string `json:"status"`
	ScheduledAt   string `json:"scheduled_at"`
	BatchSize     int    `json:"batch_size"`
	BatchDelaySec int    `json:"batch_delay_sec"`
	Sent          int    `json:"sent"`
	Failed        int    `json:"failed"`
	CreatedAt     string `json:"created_at"`
	StartedAt     string `json:"started_at"`
	CompletedAt   string `json:"completed_at"`
}

// CreateSendJob queues a campaign send at the given time (RFC3339 UTC). An
// empty or past time means "send as soon as possible".
func (s *Store) CreateSendJob(campaignID int64, scheduledAt string, batchSize, batchDelaySec int) (int64, error) {
	if batchSize < 0 {
		batchSize = 0
	}
	if batchDelaySec < 0 {
		batchDelaySec = 0
	}
	res, err := s.db.Exec(`INSERT INTO send_jobs(campaign_id, status, scheduled_at, batch_size, batch_delay_sec, sent, failed, created_at, started_at, completed_at) VALUES (?, 'pending', ?, ?, ?, 0, 0, ?, '', '')`,
		campaignID, scheduledAt, batchSize, batchDelaySec, now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListSendJobs returns all send jobs, newest first.
func (s *Store) ListSendJobs() ([]SendJob, error) {
	return s.scanSendJobs(`SELECT id, campaign_id, status, scheduled_at, batch_size, batch_delay_sec, sent, failed, created_at, started_at, completed_at FROM send_jobs ORDER BY id DESC`)
}

// DueSendJobs returns pending jobs whose scheduled time has arrived.
func (s *Store) DueSendJobs(nowStr string) ([]SendJob, error) {
	return s.scanSendJobs(`SELECT id, campaign_id, status, scheduled_at, batch_size, batch_delay_sec, sent, failed, created_at, started_at, completed_at FROM send_jobs WHERE status = 'pending' AND scheduled_at <= ? ORDER BY id`, nowStr)
}

func (s *Store) scanSendJobs(query string, args ...any) ([]SendJob, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SendJob{}
	for rows.Next() {
		var j SendJob
		if err := rows.Scan(&j.ID, &j.CampaignID, &j.Status, &j.ScheduledAt, &j.BatchSize, &j.BatchDelaySec, &j.Sent, &j.Failed, &j.CreatedAt, &j.StartedAt, &j.CompletedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// MarkSendJobRunning transitions a pending job to running.
func (s *Store) MarkSendJobRunning(id int64) error {
	_, err := s.db.Exec(`UPDATE send_jobs SET status = 'running', started_at = ? WHERE id = ? AND status = 'pending'`, now(), id)
	return err
}

// FinishSendJob records the final outcome of a job.
func (s *Store) FinishSendJob(id int64, status string, sent, failed int) error {
	_, err := s.db.Exec(`UPDATE send_jobs SET status = ?, sent = ?, failed = ?, completed_at = ? WHERE id = ?`, status, sent, failed, now(), id)
	return err
}

// CancelSendJob cancels a still-pending job.
func (s *Store) CancelSendJob(id int64) error {
	res, err := s.db.Exec(`UPDATE send_jobs SET status = 'cancelled', completed_at = ? WHERE id = ? AND status = 'pending'`, now(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("job is not pending")
	}
	return nil
}

// ResetRunningSendJobs returns any job left 'running' by a crashed process back
// to 'pending' so the scheduler retries it on restart.
func (s *Store) ResetRunningSendJobs() error {
	_, err := s.db.Exec(`UPDATE send_jobs SET status = 'pending', started_at = '' WHERE status = 'running'`)
	return err
}

// ResetCampaignSent clears the sent flag for every result in a campaign so a
// full resend can run. Opened/clicked/submitted evidence is left untouched.
func (s *Store) ResetCampaignSent(campaignID int64) error {
	_, err := s.db.Exec(`UPDATE results SET sent = 0, sent_at = '' WHERE campaign_id = ?`, campaignID)
	return err
}

// UpdateCampaignLandingPage changes the page served by an existing campaign's
// tracking links. The links themselves stay the same.
func (s *Store) UpdateCampaignLandingPage(campaignID, pageID int64) error {
	if pageID <= 0 {
		return errors.New("landing page required")
	}
	if _, err := s.GetPage(pageID); err != nil {
		return errors.New("landing page not found")
	}
	res, err := s.db.Exec(`UPDATE campaigns SET landing_page_id = ? WHERE id = ?`, pageID, campaignID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("campaign not found")
	}
	return nil
}

// UpdateCampaignSendingProfile binds or clears a campaign's sending profile.
func (s *Store) UpdateCampaignSendingProfile(campaignID, profileID int64) error {
	if profileID > 0 {
		if _, err := s.GetSendingProfile(profileID); err != nil {
			return errors.New("sending profile not found")
		}
	}
	res, err := s.db.Exec(`UPDATE campaigns SET sending_profile_id = ? WHERE id = ?`, profileID, campaignID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("campaign not found")
	}
	return nil
}

// PurgeOlderThan deletes captured submissions and tracking/behavior events
// whose timestamp predates cutoff. Campaigns, targets and result counters are
// kept so aggregate statistics survive the purge.
func (s *Store) PurgeOlderThan(cutoff time.Time) (submissions, events int64, err error) {
	ts := cutoff.UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`DELETE FROM submissions WHERE ts < ?`, ts)
	if err != nil {
		return 0, 0, err
	}
	submissions, _ = res.RowsAffected()
	res, err = s.db.Exec(`DELETE FROM events WHERE ts < ?`, ts)
	if err != nil {
		return submissions, 0, err
	}
	events, _ = res.RowsAffected()
	return submissions, events, nil
}

// ListSubmissions returns captured submissions for a campaign, newest first,
// joined with the target email.
func (s *Store) ListSubmissions(campaignID int64) ([]Submission, error) {
	rows, err := s.db.Query(`
		SELECT su.id, su.campaign_id, su.result_id, su.ts, su.ip, su.user_agent, su.referer, su.username, su.password, su.fields, t.email
		FROM submissions su
		JOIN results r ON r.id = su.result_id
		JOIN targets t ON t.id = r.target_id
		WHERE su.campaign_id = ? ORDER BY su.id DESC`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Submission{}
	for rows.Next() {
		var sub Submission
		var raw string
		if err := rows.Scan(&sub.ID, &sub.CampaignID, &sub.ResultID, &sub.TS, &sub.IP, &sub.UserAgent, &sub.Referer,
			&sub.Username, &sub.Password, &raw, &sub.Email); err != nil {
			return nil, err
		}
		sub.Password = s.decryptSecret(sub.Password)
		raw = s.decryptSecret(raw)
		sub.Fields = map[string][]string{}
		_ = json.Unmarshal([]byte(raw), &sub.Fields)
		out = append(out, sub)
	}
	return out, rows.Err()
}

// ListAllSubmissions returns every captured submission across all campaigns,
// newest first. The CSV export streams the full set, so no row cap is applied
// here; the console should page through ListSubmissions per campaign instead.
func (s *Store) ListAllSubmissions() ([]Submission, error) {
	rows, err := s.db.Query(`
		SELECT su.id, su.campaign_id, su.result_id, su.ts, su.ip, su.user_agent, su.referer, su.username, su.password, su.fields, t.email
		FROM submissions su
		JOIN results r ON r.id = su.result_id
		JOIN targets t ON t.id = r.target_id
		ORDER BY su.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Submission{}
	for rows.Next() {
		var sub Submission
		var raw string
		if err := rows.Scan(&sub.ID, &sub.CampaignID, &sub.ResultID, &sub.TS, &sub.IP, &sub.UserAgent, &sub.Referer,
			&sub.Username, &sub.Password, &raw, &sub.Email); err != nil {
			return nil, err
		}
		sub.Password = s.decryptSecret(sub.Password)
		raw = s.decryptSecret(raw)
		sub.Fields = map[string][]string{}
		_ = json.Unmarshal([]byte(raw), &sub.Fields)
		out = append(out, sub)
	}
	return out, rows.Err()
}

// ListEvents returns the timeline events for a campaign, newest first.
func (s *Store) ListEvents(campaignID int64) ([]Event, error) {
	rows, err := s.db.Query(`SELECT id, campaign_id, target_id, kind, ip, user_agent, referer, detail, ts FROM events WHERE campaign_id = ? ORDER BY id DESC`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.CampaignID, &e.TargetID, &e.Kind, &e.IP, &e.UserAgent, &e.Referer, &e.Detail, &e.TS); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecordLLMUsage appends one LLM token-usage entry.
func (s *Store) RecordLLMUsage(model string, prompt, completion, total int) {
	_, _ = s.db.Exec(`INSERT INTO llm_usage(model, prompt_tokens, completion_tokens, total_tokens, ts) VALUES (?, ?, ?, ?, ?)`,
		model, prompt, completion, total, now())
}

const ridAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// newRid returns a random 32-char tracking id.
func newRid() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	var b strings.Builder
	for i := range buf {
		b.WriteByte(ridAlphabet[int(buf[i])%len(ridAlphabet)])
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Application settings

// SettingsMap returns every runtime setting (brand name, console password
// hash, background image metadata) in one query.
func (s *Store) SettingsMap() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT k, v FROM app_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SetSetting upserts one runtime setting.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(s.sql(
		`INSERT INTO app_settings(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`,
		`INSERT INTO app_settings(k, v) VALUES(?, ?) ON DUPLICATE KEY UPDATE v = VALUES(v)`,
	), key, value)
	return err
}

// DeleteSetting removes one runtime setting.
func (s *Store) DeleteSetting(key string) error {
	_, err := s.db.Exec(`DELETE FROM app_settings WHERE k = ?`, key)
	return err
}

// ---------------------------------------------------------------------------
// Persisted application logs

// LogRow is one persisted log record.
type LogRow struct {
	ID      int64  `json:"id"`
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"msg"`
	Attrs   string `json:"-"`
}

// InsertLog appends one log row. Timestamps are normalised to UTC RFC3339 so
// retention windows compare correctly as strings.
func (s *Store) InsertLog(ts, level, msg, attrs string) error {
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		ts = t.UTC().Format(time.RFC3339)
	}
	_, err := s.db.Exec(`INSERT INTO app_logs(ts, level, msg, attrs) VALUES (?, ?, ?, ?)`, ts, level, msg, attrs)
	return err
}

// LogsSince returns logs at or after since, newest first. level filters by
// exact severity when non-empty ("ERROR"/"WARN").
func (s *Store) LogsSince(since, level string, limit int) ([]LogRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	q := `SELECT id, ts, level, msg, attrs FROM app_logs WHERE ts >= ?`
	args := []any{since}
	if level != "" {
		q += ` AND level = ?`
		args = append(args, level)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LogRow{}
	for rows.Next() {
		var r LogRow
		if err := rows.Scan(&r.ID, &r.Time, &r.Level, &r.Message, &r.Attrs); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteLogsBefore removes logs older than the cutoff timestamp.
func (s *Store) DeleteLogsBefore(cutoff string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM app_logs WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ClearLogs removes every persisted log.
func (s *Store) ClearLogs() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM app_logs`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
