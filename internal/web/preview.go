package web

import (
	"bytes"
	"fmt"
	"image/jpeg"
	"mime"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"time"

	"phishsim/internal/core/store"
	"phishsim/internal/features/clone"
	"phishsim/internal/services/hygiene"
	"phishsim/internal/services/report"
)

// ---------------------------------------------------------------------------
// Risk report

// adminReport returns a per-recipient/department risk report for one campaign.
// format=html streams a printable document; the default is JSON.
func (s *Server) adminReport(w http.ResponseWriter, r *http.Request) {
	id := parseInt(r.URL.Query().Get("campaign_id"))
	if id <= 0 {
		s.writeJSON(w, 400, map[string]any{"error": "campaign_id required"})
		return
	}
	camp, err := s.Store.GetCampaign(id)
	if err != nil {
		s.notFound(w)
		return
	}
	results, err := s.Store.ListResults(id)
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	rep := report.Build(camp, results)
	if r.URL.Query().Get("format") == "html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="phish-report-%d.html"`, id))
		_, _ = w.Write([]byte(rep.HTML()))
		return
	}
	s.writeJSON(w, 200, rep)
}

// ---------------------------------------------------------------------------
// Recipient list hygiene

// adminGroupAudit checks a group's addresses for syntax, duplicates, role
// mailboxes, disposable domains and (unless mx=0) missing MX records.
func (s *Server) adminGroupAudit(w http.ResponseWriter, r *http.Request, groupID int64) {
	targets, err := s.Store.ListGroupTargets(groupID)
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	checkMX := r.URL.Query().Get("mx") != "0"
	s.writeJSON(w, 200, hygiene.Audit(targets, checkMX, 10*time.Second))
}

// ---------------------------------------------------------------------------
// Landing page screenshot

// pageScreenshot renders a landing page and its mirrored assets through an
// in-process HTTP server, then captures a full-page PNG with headless Chrome.
func (s *Server) pageScreenshot(page store.LandingPage, timeout time.Duration) ([]byte, error) {
	return s.pageShot(page, timeout, 100)
}

// pageScreenshotJPEG renders a JPEG small enough to attach to a model turn.
func (s *Server) pageScreenshotJPEG(page store.LandingPage, timeout time.Duration) ([]byte, error) {
	return s.pageShot(page, timeout, 70)
}

func (s *Server) pageShot(page store.LandingPage, timeout time.Duration, quality int) ([]byte, error) {
	body := renderLanding(page.Body, "/p/preview")
	body = injectMobileCompat(body)
	ct := page.ContentType
	if ct == "" {
		ct = "text/html; charset=utf-8"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/p/preview/assets/", func(w http.ResponseWriter, r *http.Request) {
		sub := strings.TrimPrefix(r.URL.Path, "/p/preview/assets/")
		a, err := s.Store.GetAsset(page.ID, "/__assets__/"+sub)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		act := a.ContentType
		if act == "" {
			act = mime.TypeByExtension(path.Ext(sub))
		}
		if act == "" {
			act = "application/octet-stream"
		}
		w.Header().Set("Content-Type", act)
		_, _ = w.Write(a.Body)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write([]byte(body))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	if quality >= 100 {
		return clone.ScreenshotURL(ts.URL+"/p/preview/", timeout)
	}
	return clone.ScreenshotJPEG(ts.URL+"/p/preview/", timeout, quality)
}

// adminPagePreview serves a PNG screenshot of one landing page.
func (s *Server) adminPagePreview(w http.ResponseWriter, r *http.Request, pageID int64) {
	page, err := s.Store.GetPage(pageID)
	if err != nil {
		s.notFound(w)
		return
	}
	shot, err := s.pageScreenshot(page, 35*time.Second)
	if err != nil {
		s.writeJSON(w, 502, map[string]any{"error": "截图失败: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="page-%d.png"`, pageID))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	_, _ = w.Write(shot)
}

// jpegSize returns the pixel dimensions of a JPEG for tool summaries.
func jpegSize(data []byte) (int, int, error) {
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return 0, 0, err
	}
	return cfg.Width, cfg.Height, nil
}
