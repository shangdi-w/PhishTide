package web

// Bounce mailbox integration: read delivery status notifications over IMAP,
// attribute hard/soft failures to the campaign and recipient that produced
// them, and expose the result to the console and the agent.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"phishsim/internal/core/store"
	"phishsim/internal/services/bounce"
)

const (
	bouncePollLimit        = 50
	autoBouncePollInterval = 5 * time.Minute
)

// bounceConfig assembles the IMAP settings, reporting whether a mailbox is
// configured. ok is false when the host is empty.
func (s *Server) bounceConfig() (bounce.Config, bool) {
	st := s.appSettingsSnapshot()
	cfg := bounce.Config{
		Host:       st.BounceHost,
		Port:       st.BouncePort,
		User:       st.BounceUser,
		TLSMode:    st.BounceTLS,
		Folder:     st.BounceFolder,
		IgnoreCert: st.BounceIgnoreCert,
	}
	if st.BouncePassEnc != "" && s.Store != nil {
		cfg.Pass = s.Store.DecryptSetting(st.BouncePassEnc)
	}
	return cfg, strings.TrimSpace(cfg.Host) != ""
}

// adminBounceSecret returns the saved IMAP password for the console eye
// toggle. Every reveal is logged.
func (s *Server) adminBounceSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, 405, map[string]any{"error": "GET only"})
		return
	}
	cfg, _ := s.bounceConfig()
	s.log().Info("admin reveal imap password", "ip", s.remoteIP(r))
	s.writeJSON(w, 200, map[string]any{"password": cfg.Pass})
}

// bounceStatus is the console view of the bounce mailbox configuration.
func (s *Server) bounceStatus() map[string]any {
	st := s.appSettingsSnapshot()
	cfg, ok := s.bounceConfig()
	out := map[string]any{
		"configured":  ok,
		"host":        cfg.Host,
		"port":        cfg.Port,
		"user":        cfg.User,
		"tls_mode":    cfg.TLSMode,
		"folder":      cfg.Folder,
		"ignore_cert": cfg.IgnoreCert,
		"pass_set":    strings.TrimSpace(cfg.Pass) != "",
		"last_poll":   st.BounceLastPoll,
	}
	return out
}

// adminBounces returns the mailbox status plus recent bounces across campaigns.
func (s *Server) adminBounces(w http.ResponseWriter, r *http.Request) {
	status := s.bounceStatus()
	list, err := s.Store.ListAllBounces(300)
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	counts := map[string]int{}
	for _, b := range list {
		counts[b.Kind]++
	}
	status["bounces"] = list
	status["counts"] = counts
	s.writeJSON(w, 200, status)
}

// adminCampaignBounces lists one campaign's bounces.
func (s *Server) adminCampaignBounces(w http.ResponseWriter, r *http.Request, campaignID int64) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	list, err := s.Store.ListBounces(campaignID, limit)
	if err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	counts, _ := s.Store.CountBouncesByKind(campaignID)
	s.writeJSON(w, 200, map[string]any{"bounces": list, "count": len(list), "counts": counts})
}

// adminSaveBounceConfig stores the IMAP mailbox settings. An empty password
// keeps the stored one.
func (s *Server) adminSaveBounceConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host       string `json:"host"`
		Port       int    `json:"port"`
		User       string `json:"user"`
		Password   string `json:"password"`
		TLSMode    string `json:"tls_mode"`
		Folder     string `json:"folder"`
		IgnoreCert *bool  `json:"ignore_cert"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		s.writeJSON(w, 400, map[string]any{"error": "IMAP 服务器不能为空"})
		return
	}
	if req.Port < 0 || req.Port > 65535 {
		s.writeJSON(w, 400, map[string]any{"error": "端口必须在 1–65535"})
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.TLSMode))
	switch mode {
	case "", "starttls", "ssl":
	case "none":
		// Plaintext IMAP sends the password in the clear; only loopback is safe.
		// A stored password/user from an earlier save is just as exposed as a
		// newly typed one, so the guard must not depend on the request carrying
		// a password this time.
		if !bounce.IsLoopbackHost(host) {
			st := s.appSettingsSnapshot()
			willHaveUser := strings.TrimSpace(req.User) != "" || strings.TrimSpace(st.BounceUser) != ""
			willHavePass := req.Password != "" || st.BouncePassEnc != ""
			if willHaveUser || willHavePass {
				s.writeJSON(w, 400, map[string]any{"error": "远程主机必须使用 starttls 或 ssl"})
				return
			}
		}
	default:
		s.writeJSON(w, 400, map[string]any{"error": "tls_mode 必须是 starttls、ssl 或 none"})
		return
	}
	folder := strings.TrimSpace(req.Folder)
	if folder == "" {
		folder = "INBOX"
	}
	// Certificates are verified unless the operator explicitly opts out; a
	// bounce mailbox holds a credential, so the default must be safe.
	ignore := false
	if req.IgnoreCert != nil {
		ignore = *req.IgnoreCert
	}
	values := map[string]string{
		settingBounceHost:   host,
		settingBouncePort:   strconv.Itoa(req.Port),
		settingBounceUser:   strings.TrimSpace(req.User),
		settingBounceTLS:    mode,
		settingBounceFolder: folder,
	}
	if ignore {
		values[settingBounceIgnoreCert] = "1"
	} else {
		values[settingBounceIgnoreCert] = "0"
	}
	if pw := req.Password; pw != "" {
		values[settingBouncePass] = s.Store.EncryptSetting(pw)
	}
	for k, v := range values {
		if err := s.putSetting(k, v); err != nil {
			s.writeJSON(w, 500, map[string]any{"error": "保存失败: " + err.Error()})
			return
		}
	}
	s.writeJSON(w, 200, s.bounceStatus())
}

// bouncePollResult summarises one mailbox poll.
type bouncePollResult struct {
	Messages   int      `json:"messages"`
	NotDSN     int      `json:"not_dsn"`
	Notices    int      `json:"notices"`
	Stored     int      `json:"stored"`
	Hard       int      `json:"hard"`
	Soft       int      `json:"soft"`
	Delivered  int      `json:"delivered"`
	Unmatched  int      `json:"unmatched"`
	MarkedSeen int      `json:"marked_seen"`
	Errors     []string `json:"errors,omitempty"`
}

// adminPollBounces fetches unseen mail now and records the bounces.
func (s *Server) adminPollBounces(w http.ResponseWriter, r *http.Request) {
	cfg, ok := s.bounceConfig()
	if !ok {
		s.writeJSON(w, 400, map[string]any{"error": "尚未配置退信邮箱（IMAP）"})
		return
	}
	limit := bouncePollLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	res, err := s.pollBounces(cfg, limit)
	if err != nil {
		s.log().Error("bounce poll failed", "host", cfg.Host, "err", err)
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.log().Info("bounce poll", "host", cfg.Host, "messages", res.Messages, "hard", res.Hard,
		"soft", res.Soft, "stored", res.Stored)
	s.writeJSON(w, 200, res)
}

// pollBounces fetches the newest unseen messages, parses DSNs and records the
// per-recipient verdicts. Messages are marked seen only after processing so a
// failed connection does not lose them.
func (s *Server) pollBounces(cfg bounce.Config, limit int) (bouncePollResult, error) {
	var res bouncePollResult
	s.bounceMu.Lock()
	defer s.bounceMu.Unlock()

	client, err := bounce.Dial(cfg)
	if err != nil {
		return res, err
	}
	defer client.Close()

	msgs, err := client.ListUnseen(limit)
	if err != nil {
		return res, err
	}
	res.Messages = len(msgs)
	var uids []int
	for _, m := range msgs {
		uids = append(uids, m.UID)
		notices, ok := bounce.ParseDSN(m.Raw)
		if !ok {
			res.NotDSN++
			continue
		}
		for _, n := range notices {
			res.Notices++
			kind := bounce.KindOf(n)
			rec := store.Bounce{
				Email: n.Email, Kind: kind, Action: n.Action,
				Status: n.Status, Diagnostic: n.Diagnostic,
			}
			if r, ferr := s.Store.FindResultByEmail(n.Email); ferr == nil {
				rec.CampaignID = r.CampaignID
				rec.ResultID = r.ID
				s.Store.MarkBounced(r.ID, kind)
				s.Store.ClearSendFailure(r.CampaignID, r.ID)
			} else {
				res.Unmatched++
			}
			if err := s.Store.RecordBounce(rec); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", n.Email, err))
				continue
			}
			res.Stored++
			switch kind {
			case "hard":
				res.Hard++
				_ = s.Store.UpsertSuppression(n.Email, "hard_bounce", "退信："+truncateRunes(n.Diagnostic, 120))
			case "soft":
				res.Soft++
			case "delivered":
				res.Delivered++
			}
		}
	}
	if err := client.MarkSeen(uids); err != nil {
		res.Errors = append(res.Errors, "标记已读失败: "+err.Error())
	} else {
		res.MarkedSeen = len(uids)
	}

	stamp := time.Now().UTC().Format(time.RFC3339)
	if b, err := json.Marshal(map[string]any{
		"at": stamp, "messages": res.Messages, "hard": res.Hard,
		"soft": res.Soft, "stored": res.Stored,
	}); err == nil {
		_ = s.putSetting(settingBounceLastPoll, string(b))
	}
	return res, nil
}

// maybeAutoPollBounces polls the mailbox at most every five minutes when it is
// configured. Called from the scheduler loop.
func (s *Server) maybeAutoPollBounces() {
	cfg, ok := s.bounceConfig()
	if !ok {
		return
	}
	s.bounceMu.Lock()
	due := time.Since(s.lastBouncePoll) >= autoBouncePollInterval
	if due {
		s.lastBouncePoll = time.Now()
	}
	s.bounceMu.Unlock()
	if !due {
		return
	}
	// An unreachable IMAP server can take up to two minutes to fail; run it
	// off the scheduler goroutine so due campaign sends never wait behind it.
	// pollBounces holds bounceMu, so overlapping runs stay serialised.
	go func() {
		res, err := s.pollBounces(cfg, bouncePollLimit)
		if err != nil {
			s.log().Warn("auto bounce poll failed", "host", cfg.Host, "err", err)
			return
		}
		if res.Stored > 0 {
			s.log().Info("auto bounce poll", "hard", res.Hard, "soft", res.Soft, "stored", res.Stored)
		}
	}()
}
