package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"phishsim/internal/core/config"
	"phishsim/internal/core/store"
)

const onePixelPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="

func newSettingsTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &Server{
		Cfg: &config.Config{
			AdminUser: "admin",
			AdminPass: "oldpassword",
			AdminKey:  "test-key",
			DataDir:   t.TempDir(),
		},
		Store: st,
	}
}

func settingsRequest(s *Server, method, path string, body []byte, ct string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestSettingsBackground(t *testing.T) {
	s := newSettingsTestServer(t)

	img, _ := base64.StdEncoding.DecodeString(onePixelPNG)
	rec := settingsRequest(s, http.MethodPost, "/__admin/api/settings/background", img, "image/png")
	if rec.Code != http.StatusOK {
		t.Fatalf("background upload: %d %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	version, _ := got["background_version"].(string)
	if version == "" {
		t.Fatal("background version not set")
	}

	rec = settingsRequest(s, http.MethodGet, backgroundURL(version), nil, "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("serve background: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if !bytes.Equal(rec.Body.Bytes(), img) {
		t.Fatal("served background differs from upload")
	}

	rec = settingsRequest(s, http.MethodPost, "/__admin/api/settings/background?reset=1", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}
	rec = settingsRequest(s, http.MethodGet, "/assets/background", nil, "")
	if rec.Code != http.StatusOK || len(rec.Body.Bytes()) == len(img) {
		t.Fatalf("default background not restored: %d %d bytes", rec.Code, len(rec.Body.Bytes()))
	}
}

func TestSettingsPasswordChangeInvalidatesSessions(t *testing.T) {
	s := newSettingsTestServer(t)
	if !s.checkCredentials("admin", "oldpassword") {
		t.Fatal("old password should work before change")
	}
	token, err := s.newSessionToken()
	if err != nil {
		t.Fatal(err)
	}

	rec := settingsRequest(s, http.MethodPost, "/__admin/api/settings/password",
		[]byte(`{"current_password":"oldpassword","new_password":"newpassword123"}`), "application/json")
	if rec.Code != http.StatusOK {
		t.Fatalf("password change: %d %s", rec.Code, rec.Body.String())
	}
	if s.checkCredentials("admin", "oldpassword") {
		t.Fatal("old password still accepted")
	}
	if !s.checkCredentials("admin", "newpassword123") {
		t.Fatal("new password rejected")
	}
	if s.validSessionToken(token) {
		t.Fatal("session issued before the password change is still valid")
	}

	// Wrong current password must not rotate the credential.
	rec = settingsRequest(s, http.MethodPost, "/__admin/api/settings/password",
		[]byte(`{"current_password":"wrong","new_password":"anotherpass1"}`), "application/json")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong current password accepted: %d", rec.Code)
	}
}

func TestPublicURLOverrideAndFallback(t *testing.T) {
	s := newSettingsTestServer(t)
	s.Cfg.PublicURL = "https://launch.example:8443"

	if got := s.publicURL(); got != "https://launch.example:8443" {
		t.Fatalf("launch fallback = %q", got)
	}

	rec := settingsRequest(s, http.MethodPost, "/__admin/api/settings/public-url",
		[]byte(`{"public_url":"https://console.example:8443"}`), "application/json")
	if rec.Code != http.StatusOK {
		t.Fatalf("save public_url: %d %s", rec.Code, rec.Body.String())
	}
	if got := s.publicURL(); got != "https://console.example:8443" {
		t.Fatalf("console override = %q", got)
	}
	landing, pixel, report, unsub := s.trackingURLs("rid1")
	if landing != "https://console.example:8443/l/rid1/" ||
		pixel != "https://console.example:8443/t/rid1" ||
		report != "https://console.example:8443/r/rid1" ||
		unsub != "https://console.example:8443/u/rid1" {
		t.Fatalf("tracking URLs = %q %q %q %q", landing, pixel, report, unsub)
	}

	// A non-http(s) value is rejected and the previous value survives.
	rec = settingsRequest(s, http.MethodPost, "/__admin/api/settings/public-url",
		[]byte(`{"public_url":"ftp://bad.example"}`), "application/json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid public_url accepted: %d", rec.Code)
	}
	if got := s.publicURL(); got != "https://console.example:8443" {
		t.Fatalf("invalid save changed public_url: %q", got)
	}

	// Clearing the field removes the override and falls back to launch config.
	rec = settingsRequest(s, http.MethodPost, "/__admin/api/settings/public-url",
		[]byte(`{"public_url":""}`), "application/json")
	if rec.Code != http.StatusOK {
		t.Fatalf("clear public_url: %d %s", rec.Code, rec.Body.String())
	}
	if got := s.publicURL(); got != "https://launch.example:8443" {
		t.Fatalf("cleared override did not fall back: %q", got)
	}
}
