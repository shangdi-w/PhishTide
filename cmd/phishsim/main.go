// Command phishsim runs the phishing simulation training platform: it serves
// per-target landing pages (built-in templates or clones of real sites), email
// tracking pixels, a report-phishing endpoint, a credential/form capture
// endpoint, and an operator backend that shows captured credentials and
// submitted form data.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"phishsim/internal/core/config"
	"phishsim/internal/core/crypto"
	"phishsim/internal/core/logbuf"
	"phishsim/internal/core/store"
	"phishsim/internal/core/tlsutil"
	"phishsim/internal/features/llm"
	"phishsim/internal/services/geoip"
	"phishsim/internal/web"

	"golang.org/x/crypto/bcrypt"
)

// version is set at build time with:
//
//	go build -ldflags "-X main.version=0.1.0"
var version = "dev"

func main() {
	cfg := config.FromEnv()

	listen := flag.String("listen", cfg.Listen, "listen address")
	dataDir := flag.String("data", cfg.DataDir, "data directory")
	publicURL := flag.String("public-url", cfg.PublicURL, "public base URL used in generated links")
	adminKey := flag.String("admin-key", cfg.AdminKey, "operator backend key (empty disables /__admin)")
	adminUser := flag.String("admin-user", cfg.AdminUser, "console login username")
	adminPass := flag.String("admin-pass", cfg.AdminPass, "console login password (empty falls back to admin-key)")
	adminPassHash := flag.String("admin-pass-hash", cfg.AdminPassHash, "bcrypt hash of the console password (takes precedence)")
	trustedProxies := flag.String("trusted-proxies", strings.Join(cfg.TrustedProxies, ","), "comma-separated CIDRs whose X-Forwarded-For is honoured")
	cloneDenyPrivate := flag.Bool("clone-deny-private", cfg.CloneDenyPrivate, "refuse to clone URLs resolving to private/loopback addresses")
	geoIPDB := flag.String("geoip-db", cfg.GeoIPDB, "offline ip2asn TSV(.gz) database for IP country/operator labels (optional)")
	retentionDays := flag.Int("retention-days", cfg.RetentionDays, "purge submissions/events older than N days (0 disables)")
	maxSendTargets := flag.Int("max-send-targets", cfg.MaxSendTargets, "max pending recipients per send (0 disables)")
	failAttempts := flag.Int("fail-attempts", cfg.FailAttempts, "credential submissions answered with a wrong-password prompt before redirecting (0 disables)")
	hashPass := flag.String("hash-pass", "", "print a bcrypt hash for this password and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	certFile := flag.String("cert", cfg.CertFile, "TLS certificate file")
	keyFile := flag.String("key", cfg.KeyFile, "TLS private key file")
	smtpHost := flag.String("smtp-host", cfg.SMTPHost, "SMTP host (seeds a default sending profile)")
	smtpPort := flag.Int("smtp-port", cfg.SMTPPort, "SMTP port")
	smtpUser := flag.String("smtp-user", cfg.SMTPUser, "SMTP username")
	smtpPass := flag.String("smtp-pass", cfg.SMTPPass, "SMTP password")
	smtpTLS := flag.Bool("smtp-tls", cfg.SMTPTLS, "use STARTTLS for SMTP")
	logLevel := flag.String("log-level", "info", "debug, info, warn, error")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	cfg.Listen = *listen
	cfg.DataDir = *dataDir
	cfg.PublicURL = *publicURL
	cfg.AdminKey = *adminKey
	cfg.AdminUser = *adminUser
	cfg.AdminPass = *adminPass
	cfg.AdminPassHash = *adminPassHash
	cfg.CloneDenyPrivate = *cloneDenyPrivate
	cfg.GeoIPDB = *geoIPDB
	cfg.RetentionDays = *retentionDays
	cfg.MaxSendTargets = *maxSendTargets
	cfg.FailAttempts = *failAttempts
	if *trustedProxies != "" {
		cfg.TrustedProxies = strings.Split(*trustedProxies, ",")
		for i := range cfg.TrustedProxies {
			cfg.TrustedProxies[i] = strings.TrimSpace(cfg.TrustedProxies[i])
		}
	}

	if *hashPass != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(*hashPass), bcrypt.DefaultCost)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hash:", err)
			os.Exit(1)
		}
		fmt.Println(string(h))
		return
	}
	cfg.CertFile = *certFile
	cfg.KeyFile = *keyFile
	cfg.SMTPHost = *smtpHost
	cfg.SMTPPort = *smtpPort
	cfg.SMTPUser = *smtpUser
	cfg.SMTPPass = *smtpPass
	cfg.SMTPTLS = *smtpTLS

	if err := cfg.Finalize(); err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}

	logOut := io.Writer(os.Stdout)
	logJSON := false
	if path := strings.TrimSpace(os.Getenv("PHISH_LOG_FILE")); path != "" {
		if f, ferr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); ferr == nil {
			defer f.Close()
			logOut = io.MultiWriter(os.Stdout, f)
			logJSON = true
		}
	}
	var logHandler slog.Handler
	if logJSON {
		logHandler = slog.NewJSONHandler(logOut, &slog.HandlerOptions{Level: parseLevel(*logLevel)})
	} else {
		logHandler = slog.NewTextHandler(logOut, &slog.HandlerOptions{Level: parseLevel(*logLevel)})
	}
	logRing := logbuf.New(500, logHandler)
	logger := slog.New(logRing)
	slog.SetDefault(logger)

	// Catch a malformed PHISH_LLM_BASE_URL at boot instead of on the first
	// chat call; the console can still configure a working endpoint later.
	if cfg.LLMBaseURL != "" {
		if err := llm.ValidateBaseURL(cfg.LLMBaseURL); err != nil {
			logger.Warn("invalid PHISH_LLM_BASE_URL", "err", err)
		}
	}

	var st *store.Store
	var err error
	if cfg.DBDriver == "mysql" {
		st, err = store.OpenMySQL(cfg.DBDSN)
		if err != nil {
			logger.Error("open mysql store", "err", err)
			os.Exit(1)
		}
	} else {
		dbPath := filepath.Join(cfg.DataDir, "phishsim.db")
		st, err = store.Open(dbPath)
		if err != nil {
			logger.Error("open store", "path", dbPath, "err", err)
			os.Exit(1)
		}
	}
	defer st.Close()

	// Offline GeoIP is optional. An explicit path must load; otherwise fall
	// back to a database dropped into the data directory. The database is
	// only read locally: source IPs are never sent to a third party.
	var geoDB *geoip.DB
	if cfg.GeoIPDB == "" {
		for _, cand := range []string{
			filepath.Join(cfg.DataDir, "ip2asn-v4.tsv.gz"),
			filepath.Join(cfg.DataDir, "ip2asn-v4.tsv"),
		} {
			if _, statErr := os.Stat(cand); statErr == nil {
				cfg.GeoIPDB = cand
				break
			}
		}
	}
	if cfg.GeoIPDB != "" {
		geoDB, err = geoip.Load(cfg.GeoIPDB)
		if err != nil {
			logger.Error("load geoip database", "path", cfg.GeoIPDB, "err", err)
			os.Exit(1)
		}
		logger.Info("geoip database loaded", "path", cfg.GeoIPDB, "ranges", geoDB.Len())
	}

	// Persist logs for the console log viewer. Writes are asynchronous so a
	// slow database never blocks request handling.
	logCh := make(chan logbuf.Entry, 512)
	go func() {
		for e := range logCh {
			attrs, _ := json.Marshal(e.Attrs)
			_ = st.InsertLog(e.Time, e.Level, e.Message, string(attrs))
		}
	}()
	logRing.SetSink(func(e logbuf.Entry) {
		select {
		case logCh <- e:
		default: // drop rather than block under a log storm
		}
	})
	key, err := loadSecretKey(cfg)
	if err != nil {
		logger.Error("load secret key", "err", err)
		os.Exit(1)
	}
	st.SetSecretKey(key)

	// CLI SMTP flags seed a "默认" sending profile so a single-host deployment
	// works without any manual setup. The admin backend manages profiles too.
	if cfg.SMTPHost != "" {
		tlsMode := "starttls"
		if !cfg.SMTPTLS {
			tlsMode = "none"
		}
		if _, err := st.UpsertSendingProfile(store.SendingProfile{
			Name:          "默认",
			InterfaceType: "SMTP",
			Host:          cfg.SMTPHost,
			Port:          cfg.SMTPPort,
			Username:      cfg.SMTPUser,
			Password:      cfg.SMTPPass,
			TLSMode:       tlsMode,
			IgnoreCert:    true,
			FromEmail:     cfg.SMTPUser,
		}); err != nil {
			logger.Warn("seed sending profile", "err", err)
		}
	}

	llmClient := llm.New(cfg.LLMBaseURL, cfg.LLMKey, cfg.LLMModel)
	srv := &web.Server{Cfg: cfg, Store: st, LLM: llmClient, Log: logger, LogBuffer: logRing, SessionKey: key, Geo: geoDB}
	srv.RestoreLLMConfig()
	go srv.RunScheduler()
	go srv.RunRetention()
	srv.StartAgentWorker()

	if _, err := tlsutil.LoadOrGenerateFor(cfg.CertFile, cfg.KeyFile, certNames(cfg, srv.PublicURL())); err != nil {
		logger.Error("load TLS certificate", "err", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: cfg.ReadTimeout,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      180 * time.Second,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    64 << 10,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	logger.Info("phishing simulation platform listening",
		"version", version,
		"listen", cfg.Listen,
		"public_url", srv.PublicURL(),
		"data", cfg.DataDir,
		"admin_panel", cfg.AdminKey != "" || cfg.AdminPass != "" || cfg.AdminPassHash != "",
		"smtp_seeded", cfg.SMTPHost != "",
	)
	if err := server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile); err != nil {
		logger.Error("serve", "err", err)
		os.Exit(1)
	}
}

func certNames(cfg *config.Config, publicURL string) []string {
	if host := config.URLHost(publicURL); host != "" {
		return []string{host}
	}
	if host := config.URLHost(cfg.PublicURL); host != "" {
		return []string{host}
	}
	return nil
}

// loadSecretKey returns the AES-256 key for at-rest encryption, from
// PHISH_SECRET_KEY when set, else generating and persisting one under DataDir.
func loadSecretKey(cfg *config.Config) ([]byte, error) {
	if cfg.SecretKey != "" {
		return crypto.KeyFromHex(cfg.SecretKey)
	}
	return crypto.LoadOrCreateKey(filepath.Join(cfg.DataDir, "secret.key"))
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
