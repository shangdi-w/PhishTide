// Package config loads phishing simulation platform settings from environment
// variables and command-line flags. No external configuration library is
// required.
package config

import (
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config is the complete runtime configuration.
type Config struct {
	Listen    string
	DataDir   string
	PublicURL string
	CertFile  string
	KeyFile   string

	// DBDriver selects the storage backend: "sqlite" (default) or "mysql".
	// DBDSN is the MySQL DSN used when DBDriver is "mysql".
	DBDriver string
	DBDSN    string

	// AdminKey protects the operator backend. Empty disables /__admin.
	AdminKey string

	// AdminUser/AdminPass drive the console login form. AdminPassHash, when
	// set, is a bcrypt hash and takes precedence over AdminPass. When both are
	// empty the login form accepts AdminKey as the password (legacy setups).
	AdminUser     string
	AdminPass     string
	AdminPassHash string

	// SessionTTL is how long a console login stays valid.
	SessionTTL time.Duration

	// TrustedProxies lists CIDRs whose X-Forwarded-For header is honoured.
	// Loopback is trusted by default so a local reverse proxy/tunnel works
	// without letting arbitrary clients spoof their source IP.
	TrustedProxies []string

	// CloneDenyPrivate refuses site-clone URLs that resolve to private,
	// loopback, link-local or unspecified addresses. Off by default because
	// cloning an internal training portal is a legitimate use case.
	CloneDenyPrivate bool

	// SearchURL is an optional SearXNG base URL (e.g. http://127.0.0.1:8080).
	// When set, the console agent can search the web for reference pages; when
	// empty the search_web tool reports that search is not configured.
	SearchURL string

	// GeoIPDB is an optional offline ip2asn TSV(.gz) database used to label
	// source IPs with country and network operator. Empty means no geo
	// enrichment; lookups are always local and passive.
	GeoIPDB string

	// RetentionDays purges captured submissions and behavior/tracking events
	// older than this many days. 0 disables automatic purging.
	RetentionDays int

	// MaxSendTargets caps how many pending recipients one send may cover.
	// 0 disables the cap. Scheduled sends obey the same limit.
	MaxSendTargets int

	// FailAttempts makes the landing page answer the first N credential
	// submissions with a "wrong password" prompt and ask again, so repeated
	// passwords are captured before the visitor is redirected. 0 disables the
	// prompt and redirects on the first submission.
	FailAttempts int

	// RootRedirect makes GET / redirect to the console login instead of
	// answering 404, so operators who open the bare host or IP land on the
	// admin panel. Set PHISH_ROOT_REDIRECT=0 to restore the blank 404.
	RootRedirect bool

	// SecretKey is a 64-char hex AES-256 key for encrypting SMTP credentials at
	// rest. Empty means the platform generates and persists a key under DataDir.
	SecretKey string

	// MaskPasswords, when true, redacts captured passwords in the admin API and
	// CSV export (keeps the first two characters for triage).
	MaskPasswords bool

	// LLM settings for the AI chat / template-generation module.
	LLMBaseURL string
	LLMKey     string
	LLMModel   string
	// LLMPlanModel, when set, is used for the first agent round (planning) while
	// the regular model handles tool rounds. Optional; PHISH_LLM_PLAN_MODEL.
	LLMPlanModel string
	// LLMModelSet records whether the model came from PHISH_LLM_MODEL rather
	// than the built-in default. The console may override the default with a
	// saved model, but never an explicit deployment choice.
	LLMModelSet bool
	// LLMTemperature / LLMTemperatureSet mirror the model: 0.7 unless set.
	LLMTemperature    float64
	LLMTemperatureSet bool
	LLMModels         []string
	// LLMRatePerMin caps LLM calls per minute. 0 = unlimited.
	LLMRatePerMin int

	// SMTP settings. When Host is empty, sending is disabled and email
	// generation still works (preview + manual send).
	SMTPHost string
	SMTPPort int
	SMTPUser string
	SMTPPass string
	SMTPTLS  bool
	// SMTPRatePerSec limits the outbound send rate (emails/second). 0 = no limit.
	SMTPRatePerSec float64

	MaxBodyBytes int64
	ReadTimeout  time.Duration
	IdleTimeout  time.Duration
}

// Default returns the built-in defaults.
func Default() *Config {
	return &Config{
		Listen:         ":8443",
		DataDir:        "data",
		PublicURL:      "",
		SMTPPort:       587,
		SMTPTLS:        true,
		SMTPRatePerSec: 5,
		MaxBodyBytes:   8 << 20,
		ReadTimeout:    15 * time.Second,
		IdleTimeout:    60 * time.Second,
		AdminUser:      "admin",
		SessionTTL:     12 * time.Hour,
		TrustedProxies: []string{"127.0.0.1/32", "::1/128"},
		RetentionDays:  30,
		MaxSendTargets: 500,
		FailAttempts:   2,
		RootRedirect:   true,
	}
}

// FromEnv returns defaults overlaid with PHISH_* environment variables.
func FromEnv() *Config {
	c := Default()
	if v := os.Getenv("PHISH_LISTEN"); v != "" {
		c.Listen = v
	}
	if v := os.Getenv("PHISH_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("PHISH_PUBLIC_URL"); v != "" {
		c.PublicURL = v
	}
	if v := os.Getenv("PHISH_CERT_FILE"); v != "" {
		c.CertFile = v
	}
	if v := os.Getenv("PHISH_KEY_FILE"); v != "" {
		c.KeyFile = v
	}
	c.AdminKey = os.Getenv("PHISH_ADMIN_KEY")
	if v := os.Getenv("PHISH_ADMIN_USER"); v != "" {
		c.AdminUser = v
	}
	c.AdminPass = os.Getenv("PHISH_ADMIN_PASS")
	c.AdminPassHash = os.Getenv("PHISH_ADMIN_PASS_HASH")
	if v := os.Getenv("PHISH_SESSION_TTL"); v != "" {
		if hours, err := strconv.Atoi(v); err == nil && hours > 0 {
			c.SessionTTL = time.Duration(hours) * time.Hour
		}
	}
	if v := os.Getenv("PHISH_TRUSTED_PROXIES"); v != "" {
		c.TrustedProxies = splitList(v)
	}
	c.CloneDenyPrivate = envBool("PHISH_CLONE_DENY_PRIVATE", c.CloneDenyPrivate)
	c.SearchURL = strings.TrimRight(os.Getenv("PHISH_SEARCH_URL"), "/")
	c.GeoIPDB = os.Getenv("PHISH_GEOIP_DB")
	c.RetentionDays = envInt("PHISH_RETENTION_DAYS", c.RetentionDays)
	c.MaxSendTargets = envInt("PHISH_MAX_SEND_TARGETS", c.MaxSendTargets)
	c.FailAttempts = envInt("PHISH_FAIL_ATTEMPTS", c.FailAttempts)
	c.RootRedirect = envBool("PHISH_ROOT_REDIRECT", c.RootRedirect)
	c.SecretKey = os.Getenv("PHISH_SECRET_KEY")
	c.DBDriver = os.Getenv("PHISH_DB_DRIVER")
	c.DBDSN = os.Getenv("PHISH_DB_DSN")
	c.MaskPasswords = envBool("PHISH_MASK_PASSWORDS", false)
	c.LLMBaseURL = os.Getenv("PHISH_LLM_BASE_URL")
	c.LLMKey = os.Getenv("PHISH_LLM_KEY")
	c.LLMModel = os.Getenv("PHISH_LLM_MODEL")
	c.LLMModelSet = c.LLMModel != ""
	c.LLMPlanModel = strings.TrimSpace(os.Getenv("PHISH_LLM_PLAN_MODEL"))
	if !c.LLMModelSet {
		c.LLMModel = "deepseek-flash"
	}
	c.LLMTemperature = 0.7
	if v := os.Getenv("PHISH_LLM_TEMPERATURE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f <= 2 {
			c.LLMTemperature = f
			c.LLMTemperatureSet = true
		}
	}
	if v := os.Getenv("PHISH_LLM_MODELS"); v != "" {
		c.LLMModels = splitList(v)
	} else {
		c.LLMModels = []string{"deepseek-flash", "deepseek-chat", "deepseek-reasoner", "gpt-4o", "gpt-4o-mini"}
	}
	c.LLMRatePerMin = envInt("PHISH_LLM_RATE_PER_MIN", 30)
	if v := os.Getenv("PHISH_SMTP_HOST"); v != "" {
		c.SMTPHost = v
	}
	c.SMTPPort = envInt("PHISH_SMTP_PORT", c.SMTPPort)
	if v := os.Getenv("PHISH_SMTP_USER"); v != "" {
		c.SMTPUser = v
	}
	if v := os.Getenv("PHISH_SMTP_PASS"); v != "" {
		c.SMTPPass = v
	}
	c.SMTPTLS = envBool("PHISH_SMTP_TLS", c.SMTPTLS)
	c.SMTPRatePerSec = envFloat("PHISH_SMTP_RATE", c.SMTPRatePerSec)
	c.MaxBodyBytes = int64(envInt("PHISH_MAX_BODY_BYTES", int(c.MaxBodyBytes)))
	return c
}

// Finalize derives the public URL when it was left empty and creates the data
// directory.
func (c *Config) Finalize() error {
	if c.MaxBodyBytes < 1024 {
		c.MaxBodyBytes = 1024
	}
	if c.PublicURL == "" {
		c.PublicURL = derivePublicURL(c.Listen)
	}
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	if c.CertFile == "" {
		c.CertFile = filepath.Join(c.DataDir, "tls", "cert.pem")
	}
	if c.KeyFile == "" {
		c.KeyFile = filepath.Join(c.DataDir, "tls", "key.pem")
	}
	if err := os.MkdirAll(c.DataDir, 0o750); err != nil {
		return err
	}
	return nil
}

func derivePublicURL(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "https://127.0.0.1:8443"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "https://" + net.JoinHostPort(host, port)
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func envFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

// URLHost returns the hostname of a URL, or "" on failure.
func URLHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// splitList parses a comma-separated list, dropping blank entries.
func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
