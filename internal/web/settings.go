package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Runtime settings stored in the app_settings table. They override the values
// baked into the binary at launch, so the operator can rename the platform,
// change the console password and swap the background from the UI.
const (
	settingPublicURL    = "public_url"
	settingAdminHash    = "admin_pass_hash"
	settingBackgroundKV = "background_version"
	settingBackgroundCT = "background_type"
	settingLogRetention = "log_retention_days"

	// LLM settings saved from the console. The API key is sealed with the
	// platform secret key (enc:v1:) before it is written to app_settings.
	settingLLMBaseURL     = "llm_base_url"
	settingLLMModel       = "llm_model"
	settingLLMPlanModel   = "llm_plan_model"
	settingLLMKey         = "llm_key"
	settingLLMTemperature = "llm_temperature"

	// Bounce mailbox (IMAP) settings. The password is sealed like the LLM key.
	settingBounceHost       = "bounce_imap_host"
	settingBouncePort       = "bounce_imap_port"
	settingBounceUser       = "bounce_imap_user"
	settingBouncePass       = "bounce_imap_pass"
	settingBounceTLS        = "bounce_imap_tls"
	settingBounceFolder     = "bounce_imap_folder"
	settingBounceIgnoreCert = "bounce_imap_ignore_cert"
	settingBounceLastPoll   = "bounce_last_poll"

	// Fixed display name; the console no longer lets the operator rename it.
	displayBrandName    = "PhishTide"
	displayBrandTagline = "钓鱼演练平台"

	maxBackground       = 5 << 20 // 5 MiB
	defaultLogRetention = 7
	minPasswordLen      = 8
)

type appSettings struct {
	PublicURL         string
	AdminHash         string
	BackgroundType    string
	BackgroundVersion string
	LogRetentionDays  int
	LLMBaseURL        string
	LLMModel          string
	LLMPlanModel      string
	LLMKeyEnc         string
	LLMTemperature    string

	BounceHost       string
	BouncePort       int
	BounceUser       string
	BouncePassEnc    string
	BounceTLS        string
	BounceFolder     string
	BounceIgnoreCert bool
	BounceLastPoll   string
}

func defaultAppSettings() appSettings {
	return appSettings{LogRetentionDays: defaultLogRetention}
}

// appSettingsSnapshot returns the cached settings, loading them on first use.
func (s *Server) appSettingsSnapshot() appSettings {
	s.settingsMu.RLock()
	if s.settingsLoaded {
		v := s.settingsCache
		s.settingsMu.RUnlock()
		return v
	}
	s.settingsMu.RUnlock()

	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	if !s.settingsLoaded {
		s.loadSettingsLocked()
	}
	return s.settingsCache
}

func (s *Server) loadSettingsLocked() {
	s.settingsCache = defaultAppSettings()
	s.settingsLoaded = true
	if s.Store == nil {
		return
	}
	m, err := s.Store.SettingsMap()
	if err != nil {
		return
	}
	s.settingsCache.PublicURL = strings.TrimRight(strings.TrimSpace(m[settingPublicURL]), "/")
	s.settingsCache.AdminHash = m[settingAdminHash]
	s.settingsCache.BackgroundType = m[settingBackgroundCT]
	s.settingsCache.BackgroundVersion = m[settingBackgroundKV]
	s.settingsCache.LLMBaseURL = strings.TrimSpace(m[settingLLMBaseURL])
	s.settingsCache.LLMModel = strings.TrimSpace(m[settingLLMModel])
	s.settingsCache.LLMPlanModel = strings.TrimSpace(m[settingLLMPlanModel])
	s.settingsCache.LLMKeyEnc = m[settingLLMKey]
	s.settingsCache.LLMTemperature = strings.TrimSpace(m[settingLLMTemperature])
	s.settingsCache.BounceHost = strings.TrimSpace(m[settingBounceHost])
	s.settingsCache.BounceUser = strings.TrimSpace(m[settingBounceUser])
	s.settingsCache.BouncePassEnc = m[settingBouncePass]
	s.settingsCache.BounceTLS = strings.TrimSpace(m[settingBounceTLS])
	s.settingsCache.BounceFolder = strings.TrimSpace(m[settingBounceFolder])
	s.settingsCache.BounceLastPoll = strings.TrimSpace(m[settingBounceLastPoll])
	if v := strings.TrimSpace(m[settingBouncePort]); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			s.settingsCache.BouncePort = n
		}
	}
	if v := strings.TrimSpace(m[settingBounceIgnoreCert]); v != "" {
		s.settingsCache.BounceIgnoreCert = v == "1" || strings.EqualFold(v, "true")
	}
	if v := m[settingLogRetention]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			s.settingsCache.LogRetentionDays = n
		}
	}
}

func (s *Server) refreshSettings() {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	s.loadSettingsLocked()
}

func (s *Server) putSetting(key, value string) error {
	if s.Store == nil {
		return errors.New("store not configured")
	}
	if err := s.Store.SetSetting(key, value); err != nil {
		return err
	}
	s.refreshSettings()
	return nil
}

func (s *Server) deleteSetting(key string) error {
	if s.Store == nil {
		return errors.New("store not configured")
	}
	if err := s.Store.DeleteSetting(key); err != nil {
		return err
	}
	s.refreshSettings()
	return nil
}

// backgroundPath is where an uploaded background lives.
func (s *Server) backgroundPath() string {
	return filepath.Join(s.Cfg.DataDir, "background.img")
}

// settingsJSON is the shape returned to the console.
func (s *Server) settingsJSON() map[string]any {
	st := s.appSettingsSnapshot()
	return map[string]any{
		"public_url":         s.publicURL(),
		"background_version": st.BackgroundVersion,
		"background_url":     backgroundURL(st.BackgroundVersion),
		"log_retention_days": st.LogRetentionDays,
	}
}

// PublicURL returns the effective public base URL: the console setting when
// present, otherwise the launch-time -public-url / PHISH_PUBLIC_URL value.
func (s *Server) PublicURL() string { return s.publicURL() }

func (s *Server) publicURL() string {
	if s != nil {
		if v := strings.TrimRight(strings.TrimSpace(s.appSettingsSnapshot().PublicURL), "/"); v != "" {
			return v
		}
		if s.Cfg != nil {
			return strings.TrimRight(strings.TrimSpace(s.Cfg.PublicURL), "/")
		}
	}
	return ""
}

// trackingURLs builds the per-target landing, pixel, report, and unsubscribe
// links from the effective public URL, so a console-side change takes effect
// for the next send without a restart.
func (s *Server) trackingURLs(rid string) (landing, pixel, report, unsubscribe string) {
	base := s.publicURL()
	return base + "/l/" + rid + "/", base + "/t/" + rid, base + "/r/" + rid, base + "/u/" + rid
}

func backgroundURL(version string) string {
	if version == "" {
		return "/assets/background"
	}
	return "/assets/background?v=" + version
}

// adminGetSettings returns the current runtime settings.
func (s *Server) adminGetSettings(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, s.settingsJSON())
}

// adminSavePublicURL updates the base URL used in generated links. An empty
// value removes the override and falls back to the launch-time -public-url.
func (s *Server) adminSavePublicURL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicURL string `json:"public_url"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	publicURL := strings.TrimRight(strings.TrimSpace(req.PublicURL), "/")
	if publicURL != "" {
		if len(publicURL) > 512 {
			s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "对外地址过长"})
			return
		}
		u, err := url.Parse(publicURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "对外地址必须是完整的 http/https 地址，例如 https://phish.example.com:8443"})
			return
		}
	}
	if publicURL == "" {
		_ = s.deleteSetting(settingPublicURL)
	} else if err := s.putSetting(settingPublicURL, publicURL); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	s.log().Info("public url updated", "public_url", s.publicURL(), "ip", s.remoteIP(r))
	s.writeJSON(w, http.StatusOK, s.settingsJSON())
}

// adminSavePassword rotates the console password. The current password is
// required; the new hash is stored in app_settings and takes precedence over
// the launch flags. Because the session signing key mixes in the credential,
// every existing session is invalidated by the change.
func (s *Server) adminSavePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	if !s.checkCredentials(s.Cfg.AdminUser, req.CurrentPassword) {
		s.writeJSON(w, http.StatusForbidden, map[string]any{"error": "当前密码不正确"})
		return
	}
	if len(req.NewPassword) < minPasswordLen {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "新密码至少 8 位"})
		return
	}
	if len(req.NewPassword) > 128 {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "新密码过长"})
		return
	}
	if req.NewPassword == req.CurrentPassword {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "新密码不能与当前密码相同"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "生成密码哈希失败"})
		return
	}
	if err := s.putSetting(settingAdminHash, string(hash)); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	s.clearSessionCookies(w)
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "relogin": true})
}

// adminUploadBackground stores a new background image. The bytes go to
// <data>/background.img; the type and a content hash live in app_settings so
// the public URL can bust caches.
func (s *Server) adminUploadBackground(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("reset") == "1" {
		_ = s.deleteSetting(settingBackgroundKV)
		_ = s.deleteSetting(settingBackgroundCT)
		_ = os.Remove(s.backgroundPath())
		s.writeJSON(w, http.StatusOK, s.settingsJSON())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBackground)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "图片超过 5MB"})
		return
	}
	if len(data) == 0 {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "图片为空"})
		return
	}
	ct := http.DetectContentType(data)
	switch ct {
	case "image/png", "image/jpeg", "image/webp", "image/gif":
	default:
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "只支持 PNG / JPEG / WebP / GIF"})
		return
	}
	if err := os.MkdirAll(s.Cfg.DataDir, 0o755); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	tmp := s.backgroundPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if err := os.Rename(tmp, s.backgroundPath()); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	sum := sha256.Sum256(data)
	version := hex.EncodeToString(sum[:8])
	if err := s.putSetting(settingBackgroundCT, ct); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if err := s.putSetting(settingBackgroundKV, version); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, http.StatusOK, s.settingsJSON())
}

// serveBackground serves the uploaded background or the embedded default. It
// is public because the login page needs it before authentication.
func (s *Server) serveBackground(w http.ResponseWriter, r *http.Request) {
	st := s.appSettingsSnapshot()
	if st.BackgroundVersion != "" {
		if data, err := os.ReadFile(s.backgroundPath()); err == nil && len(data) > 0 {
			etag := `"` + st.BackgroundVersion + `"`
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("Content-Type", st.BackgroundType)
			w.Header().Set("ETag", etag)
			w.Header().Set("Cache-Control", "public, max-age=86400")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
			return
		}
	}
	data, err := staticFS.ReadFile("static/vendor/admin-bg.png")
	if err != nil {
		s.notFound(w)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
