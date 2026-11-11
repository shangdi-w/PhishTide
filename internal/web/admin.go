package web

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"phishsim/internal/core/store"
	"phishsim/internal/features/clone"
	"phishsim/internal/features/email"
	"phishsim/internal/features/llm"
	"phishsim/internal/services/analyze"
	"phishsim/internal/services/dnscheck"
)

// adminOverview returns campaigns, templates, landing pages, groups, and
// sending profiles for the operator console.
func (s *Server) adminOverview(w http.ResponseWriter, r *http.Request) {
	campaigns, err := s.Store.ListCampaigns()
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	templates, _ := s.Store.ListTemplates()
	pages, _ := s.Store.ListPages()
	groups, _ := s.Store.ListGroups()
	profiles, _ := s.Store.ListSendingProfiles()
	s.writeJSON(w, 200, map[string]any{
		"campaigns":        campaigns,
		"templates":        templates,
		"pages":            pages,
		"groups":           groups,
		"profiles":         profiles,
		"retention_days":   s.Cfg.RetentionDays,
		"max_send_targets": s.Cfg.MaxSendTargets,
		"public_url":       s.publicURL(),
	})
}

// adminCreateCampaign creates a campaign from selected groups.
func (s *Server) adminCreateCampaign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name             string  `json:"name"`
		EmailTemplateID  int64   `json:"email_template_id"`
		EmailTemplateBID int64   `json:"email_template_b_id"`
		ABSplit          int     `json:"ab_split"`
		LandingPageID    int64   `json:"landing_page_id"`
		SendingProfileID int64   `json:"sending_profile_id"`
		GroupIDs         []int64 `json:"group_ids"`
		LinkTTLHours     int     `json:"link_ttl_hours"`
		LinkOnce         bool    `json:"link_once"`
		IPAllow          string  `json:"ip_allow"`
		IPDeny           string  `json:"ip_deny"`
		SeedEmails       string  `json:"seed_emails"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json: " + err.Error()})
		return
	}
	if req.Name == "" {
		s.writeJSON(w, 400, map[string]any{"error": "name required"})
		return
	}
	if req.EmailTemplateID <= 0 {
		s.writeJSON(w, 400, map[string]any{"error": "请选择邮件模板"})
		return
	}
	if req.LandingPageID == 0 {
		req.LandingPageID = s.Store.TemplateDefaultPage(req.EmailTemplateID)
	}
	if req.LandingPageID <= 0 {
		s.writeJSON(w, 400, map[string]any{"error": "请选择钓鱼网站（落地页），否则邮件链接会 404"})
		return
	}
	if _, err := s.Store.GetTemplate(req.EmailTemplateID); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "邮件模板不存在"})
		return
	}
	if _, err := s.Store.GetPage(req.LandingPageID); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "落地页不存在"})
		return
	}
	if len(req.GroupIDs) == 0 {
		s.writeJSON(w, 400, map[string]any{"error": "at least one group required"})
		return
	}
	if req.EmailTemplateBID > 0 {
		if req.EmailTemplateBID == req.EmailTemplateID {
			s.writeJSON(w, 400, map[string]any{"error": "B 模板不能与 A 模板相同"})
			return
		}
		if _, err := s.Store.GetTemplate(req.EmailTemplateBID); err != nil {
			s.writeJSON(w, 400, map[string]any{"error": "B 模板不存在"})
			return
		}
		if req.ABSplit == 0 {
			req.ABSplit = 50
		}
	} else {
		req.ABSplit = 0
	}
	if req.ABSplit < 0 || req.ABSplit > 100 {
		s.writeJSON(w, 400, map[string]any{"error": "A/B 分流比例需在 0–100 之间"})
		return
	}
	if req.LinkTTLHours < 0 || req.LinkTTLHours > 24*365 {
		s.writeJSON(w, 400, map[string]any{"error": "链接有效期需在 0–8760 小时之间"})
		return
	}
	if req.SendingProfileID > 0 {
		if _, err := s.Store.GetSendingProfile(req.SendingProfileID); err != nil {
			s.writeJSON(w, 400, map[string]any{"error": "发件账号不存在"})
			return
		}
	}
	if bad := invalidIPList(req.IPAllow); len(bad) > 0 {
		s.writeJSON(w, 400, map[string]any{"error": "允许名单含无效 IP/CIDR: " + strings.Join(bad, ", ")})
		return
	}
	if bad := invalidIPList(req.IPDeny); len(bad) > 0 {
		s.writeJSON(w, 400, map[string]any{"error": "拒绝名单含无效 IP/CIDR: " + strings.Join(bad, ", ")})
		return
	}
	sendSeeds := splitSeedEmails(req.SeedEmails)
	if bad := invalidSeedList(req.SeedEmails); len(bad) > 0 {
		s.writeJSON(w, 400, map[string]any{"error": "种子邮箱格式异常: " + strings.Join(bad, ", ")})
		return
	}
	id, err := s.Store.CreateCampaign(store.Campaign{
		Name:             req.Name,
		EmailTemplateID:  req.EmailTemplateID,
		EmailTemplateBID: req.EmailTemplateBID,
		ABSplit:          req.ABSplit,
		LandingPageID:    req.LandingPageID,
		SendingProfileID: req.SendingProfileID,
		LinkTTLHours:     req.LinkTTLHours,
		LinkOnce:         req.LinkOnce,
		IPAllow:          strings.TrimSpace(req.IPAllow),
		IPDeny:           strings.TrimSpace(req.IPDeny),
		SeedEmails:       strings.Join(sendSeeds, "\n"),
	}, req.GroupIDs)
	if err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"id": id})
}

// adminDeleteCampaign removes a campaign and all of its owned rows.
func (s *Server) adminDeleteCampaign(w http.ResponseWriter, r *http.Request, id int64) {
	camp, cerr := s.Store.GetCampaign(id)
	if err := s.Store.SoftDeleteCampaign(id); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if cerr == nil {
		_ = s.Store.RecordDeletedCampaign(store.DeletedCampaign{
			CampaignID: id, Name: camp.Name, Targets: camp.Targets, Sent: camp.Sent,
		})
		s.log().Info("campaign soft-deleted", "campaign", id, "name", camp.Name,
			"targets", camp.Targets, "sent", camp.Sent, "ip", s.remoteIP(r))
	}
	s.writeJSON(w, 200, map[string]any{"deleted": id, "recycle": true})
}

// adminRestoreCampaign restores a campaign from the recycle bin.
func (s *Server) adminRestoreCampaign(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	if err := s.Store.RestoreCampaign(id); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.log().Info("campaign restored", "campaign", id, "ip", s.remoteIP(r))
	s.writeJSON(w, 200, map[string]any{"restored": id})
}

// adminPurgeCampaign permanently removes a recycled campaign and every row it owns.
func (s *Server) adminPurgeCampaign(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	camp, err := s.Store.GetCampaign(id)
	if err != nil {
		s.notFound(w)
		return
	}
	if camp.DeletedAt == "" {
		s.writeJSON(w, 400, map[string]any{"error": "只能彻底删除回收站中的活动，请先移入回收站"})
		return
	}
	if err := s.Store.DeleteCampaign(id); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.log().Info("campaign purged", "campaign", id, "name", camp.Name, "ip", s.remoteIP(r))
	s.writeJSON(w, 200, map[string]any{"purged": id})
}

// adminDeletedCampaigns lists the recycle bin.
func (s *Server) adminDeletedCampaigns(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListCampaignsInRecycleBin()
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"campaigns": list})
}

// adminRenameCampaign renames a campaign.
func (s *Server) adminRenameCampaign(w http.ResponseWriter, r *http.Request, id int64) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json: " + err.Error()})
		return
	}
	if err := s.Store.RenameCampaign(id, req.Name); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"renamed": id})
}

// adminDeleteGroup removes a group and its targets.
func (s *Server) adminDeleteGroup(w http.ResponseWriter, r *http.Request, id int64) {
	if names, err := s.Store.CampaignsUsingGroup(id); err == nil && len(names) > 0 {
		s.writeJSON(w, 400, map[string]any{"error": "该群组仍被活动" + store.ReferencedBy(names) + "使用（含回收站），请先改绑或彻底处理这些活动"})
		return
	}
	if err := s.Store.DeleteGroup(id); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"deleted": id})
}

// adminRenameGroup renames a group.
func (s *Server) adminRenameGroup(w http.ResponseWriter, r *http.Request, id int64) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json: " + err.Error()})
		return
	}
	if err := s.Store.RenameGroup(id, req.Name); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"renamed": id})
}

// adminDeletePage removes a landing page and its assets.
func (s *Server) adminDeletePage(w http.ResponseWriter, r *http.Request, id int64) {
	if names, err := s.Store.CampaignsUsingPage(id); err == nil && len(names) > 0 {
		s.writeJSON(w, 400, map[string]any{"error": "该落地页仍被活动" + store.ReferencedBy(names) + "使用（含回收站），请先改绑或彻底处理这些活动"})
		return
	}
	if err := s.Store.DeletePage(id); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"deleted": id})
}

// adminRenamePage renames a landing page.
func (s *Server) adminRenamePage(w http.ResponseWriter, r *http.Request, id int64) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json: " + err.Error()})
		return
	}
	if err := s.Store.RenamePage(id, req.Name); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"renamed": id})
}

// adminDeleteTemplate removes an email template (and cascade-deletes campaigns
// that reference it).
func (s *Server) adminDeleteTemplate(w http.ResponseWriter, r *http.Request, id int64) {
	if names, err := s.Store.CampaignsUsingTemplate(id); err == nil && len(names) > 0 {
		s.writeJSON(w, 400, map[string]any{"error": "该模板仍被活动" + store.ReferencedBy(names) + "使用（含回收站），请先改绑或彻底处理这些活动"})
		return
	}
	if err := s.Store.DeleteTemplate(id); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"deleted": id})
}

// adminRenameTemplate renames an email template.
func (s *Server) adminRenameTemplate(w http.ResponseWriter, r *http.Request, id int64) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json: " + err.Error()})
		return
	}
	if err := s.Store.RenameTemplate(id, req.Name); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"renamed": id})
}

// adminDeleteCampaignResult removes one target from a campaign.
func (s *Server) adminDeleteCampaignResult(w http.ResponseWriter, r *http.Request, campaignID, resultID int64) {
	if err := s.Store.DeleteCampaignResult(campaignID, resultID); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"deleted": resultID})
}

// adminCampaignProfile binds a sending profile to an existing campaign.
func (s *Server) adminCampaignProfile(w http.ResponseWriter, r *http.Request, id int64) {
	var req struct {
		SendingProfileID int64 `json:"sending_profile_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	if err := s.Store.UpdateCampaignSendingProfile(id, req.SendingProfileID); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"campaign_id": id, "sending_profile_id": req.SendingProfileID})
}

// adminCampaignLandingPage changes the landing page of an existing campaign.
func (s *Server) adminCampaignLandingPage(w http.ResponseWriter, r *http.Request, id int64) {
	var req struct {
		LandingPageID int64 `json:"landing_page_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	if err := s.Store.UpdateCampaignLandingPage(id, req.LandingPageID); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"campaign_id": id, "landing_page_id": req.LandingPageID})
}

// adminCampaign returns a campaign and its per-target results.
func (s *Server) adminCampaign(w http.ResponseWriter, r *http.Request, id int64) {
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
	landing := map[string]any{}
	if page, err := s.Store.GetPage(camp.LandingPageID); err == nil {
		landing = map[string]any{
			"id":                  page.ID,
			"name":                page.Name,
			"capture_credentials": page.CaptureCredentials,
			"capture_passwords":   page.CapturePasswords,
		}
	}
	bounces, _ := s.Store.ListBounces(id, 200)
	bounceCounts, _ := s.Store.CountBouncesByKind(id)
	s.writeJSON(w, 200, map[string]any{
		"campaign":      camp,
		"results":       results,
		"public_url":    s.publicURL(),
		"landing_page":  landing,
		"bounces":       bounces,
		"bounce_counts": bounceCounts,
	})
}

// adminSubmissions returns the captured submissions for a campaign.
func (s *Server) adminSubmissions(w http.ResponseWriter, r *http.Request, id int64) {
	subs, err := s.Store.ListSubmissions(id)
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.enrichSubmissions(subs)
	for i := range subs {
		subs[i].Password = s.mask(subs[i].Password)
	}
	s.writeJSON(w, 200, map[string]any{"submissions": subs})
}

// adminSubmissionsExport streams every captured submission as a single CSV,
// with one column per distinct captured form field.
func (s *Server) adminSubmissionsExport(w http.ResponseWriter, r *http.Request) {
	subs, err := s.Store.ListAllSubmissions()
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.enrichSubmissions(subs)
	fieldNames := map[string]bool{}
	for _, sub := range subs {
		for k := range sub.Fields {
			fieldNames[k] = true
		}
	}
	fieldCols := sortedStringSet(fieldNames)

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="submissions.csv"`)
	// A UTF-8 BOM makes Excel/WPS read Chinese names and fields correctly.
	_, _ = w.Write([]byte("\xEF\xBB\xBF"))
	wr := csv.NewWriter(w)
	header := []string{"time", "campaign_id", "email", "username", "password", "ip", "country", "org", "user_agent", "referer"}
	header = append(header, fieldCols...)
	sanitizeCSVRow(header)
	_ = wr.Write(header)
	for _, sub := range subs {
		row := []string{sub.TS, fmt.Sprintf("%d", sub.CampaignID), sub.Email, sub.Username, s.mask(sub.Password), sub.IP, sub.Country, sub.Org, sub.UserAgent, sub.Referer}
		for _, f := range fieldCols {
			row = append(row, joinValues(sub.Fields[f]))
		}
		sanitizeCSVRow(row)
		_ = wr.Write(row)
	}
	wr.Flush()
}

// adminEvents returns the timeline of behavior + tracking events.
func (s *Server) adminEvents(w http.ResponseWriter, r *http.Request, id int64) {
	events, err := s.Store.ListEvents(id)
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"events": events})
}

// adminTerminate stops a campaign immediately (emergency kill switch).
func (s *Server) adminTerminate(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, 405, map[string]any{"error": "POST required"})
		return
	}
	if err := s.Store.TerminateCampaign(id); err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"terminated": id})
}

// adminDNSCheck validates a domain's SPF/DKIM/DMARC records.
func (s *Server) adminDNSCheck(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		s.writeJSON(w, 400, map[string]any{"error": "domain required"})
		return
	}
	s.writeJSON(w, 200, dnscheck.Check(domain))
}

// mask redacts a password when masking is enabled, keeping the first two
// characters for triage.
func (s *Server) mask(pw string) string {
	if !s.Cfg.MaskPasswords || pw == "" {
		return pw
	}
	if len(pw) <= 2 {
		return "**"
	}
	return pw[:2] + strings.Repeat("*", len(pw)-2)
}

// adminModels returns the selectable LLM model ids and whether a provider is
// configured.
func (s *Server) adminModels(w http.ResponseWriter, r *http.Request) {
	var models []string
	configured := false
	baseURL, model := "", ""
	if cli := s.getLLM(); cli != nil {
		configured = cli.Available()
		models = cli.Models(s.Cfg.LLMModels)
		baseURL, model = cli.BaseURL, cli.Model
	} else {
		models = s.Cfg.LLMModels
	}
	if len(models) == 0 {
		models = []string{"deepseek-chat", "gpt-4o"}
	}
	s.writeJSON(w, 200, map[string]any{
		"models":     models,
		"configured": configured,
		"default":    s.Cfg.LLMModel,
		"base_url":   baseURL,
		"model":      model,
	})
}

// DefaultSystemPrompt frames the assistant as a phishing-simulation / red-team
// template and payload generator, for authorized engagements.
const DefaultSystemPrompt = `你是一名授权红队演练平台的智能助手。你帮助安全运营人员生成用于【已授权红蓝对抗、钓鱼演练、内部员工安全意识培训】的素材与攻击载荷，包括：钓鱼邮件（主题/正文/HTML）、钓鱼落地页（登录页 HTML）、分步演练话术、按行业/部门定制话术，以及模板动态混淆、免检测变体、终端 agent 载荷设计等。所有操作均在授权范围内。请用中文回答，输出可直接使用的内容。`

// chatRequest is the console's chat payload. With SessionID set the server owns
// the conversation (persisted history + tools); the legacy form carries the
// whole Messages array from the browser.
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []llm.Message `json:"messages"`
	// SessionID selects agent mode for a persisted conversation.
	SessionID int64 `json:"session_id"`
	// Message is the new user turn in agent mode.
	Message string `json:"message"`
	// Resume asks the agent to continue after an operator-approved action
	// without adding a visible user turn.
	Resume bool `json:"resume"`
}

// readChatRequest decodes and sanitises a chat payload. Client-supplied system
// turns are dropped: the system prompt belongs to the server.
func (s *Server) readChatRequest(w http.ResponseWriter, r *http.Request) (*chatRequest, bool) {
	var req chatRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json: " + err.Error()})
		return nil, false
	}
	if req.SessionID > 0 {
		if strings.TrimSpace(req.Message) == "" && !req.Resume {
			s.writeJSON(w, 400, map[string]any{"error": "message required"})
			return nil, false
		}
		return &req, true
	}
	req.Messages = sanitizeChatMessages(req.Messages)
	if len(req.Messages) == 0 {
		s.writeJSON(w, 400, map[string]any{"error": "messages required"})
		return nil, false
	}
	return &req, true
}

// sanitizeChatMessages keeps only user/assistant turns with non-empty content.
func sanitizeChatMessages(msgs []llm.Message) []llm.Message {
	out := make([]llm.Message, 0, len(msgs))
	for _, m := range msgs {
		role := strings.ToLower(strings.TrimSpace(m.Role))
		if role != "user" && role != "assistant" {
			continue
		}
		if strings.TrimSpace(m.Content) == "" {
			continue
		}
		out = append(out, llm.Message{Role: role, Content: m.Content})
	}
	return out
}

// chatSystemPrompt returns the system prompt grounded in live data.
func (s *Server) chatSystemPrompt() string {
	sys := DefaultSystemPrompt
	if snap, err := analyze.BuildCached(s.Store, 30*time.Second, s.geoLookup); err == nil {
		if txt := snap.Text(); txt != "" {
			sys += "\n\n当前平台数据（回答数据类问题时请据此作答）：\n" + txt
		}
	}
	return sys
}

// adminChatStream streams one chat completion to the console as SSE. Each
// frame is {"delta": "..."}; the final frame carries {"done": true, "usage":
// {...}}, and a failure arriving after the stream opened is reported as
// {"error": "..."}.
func (s *Server) adminChatStream(w http.ResponseWriter, r *http.Request) {
	cli := s.getLLM()
	if cli == nil || !cli.Available() {
		s.writeJSON(w, 400, map[string]any{"error": "LLM 未配置：请在「AI 对话」页填写 Base URL（本地服务可不填 API Key）"})
		return
	}
	if !s.allowLLMCall(r, s.Cfg.LLMRatePerMin) {
		s.writeJSON(w, 429, map[string]any{"error": "调用过于频繁，请稍后再试"})
		return
	}
	req, ok := s.readChatRequest(w, r)
	if !ok {
		return
	}
	if req.SessionID > 0 {
		s.chatStreamAgent(w, r, cli, req)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeJSON(w, 500, map[string]any{"error": "当前连接不支持流式输出"})
		return
	}
	// The server-wide WriteTimeout would cut a long stream; the request context
	// below is the real bound, so clear the per-connection write deadline.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	history := trimChatHistory(req.Messages, maxChatTurns, maxChatRunes)
	msgs := append([]llm.Message{{Role: "system", Content: s.chatSystemPrompt()}}, history...)

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// nginx and friends must not buffer the stream.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	// A failed write means the browser went away (the "stop" button or a closed
	// tab). Return the error so ChatStream aborts and the upstream request is
	// cancelled instead of the server paying for tokens nobody reads.
	send := func(v any) error {
		data, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	model := strings.TrimSpace(req.Model)
	_, usage, err := cli.ChatStream(ctx, model, msgs, func(delta string) error {
		return send(map[string]any{"delta": delta})
	})
	if err != nil {
		if r.Context().Err() != nil {
			return // client disconnected; nothing left to tell it
		}
		_ = send(map[string]any{"error": err.Error()})
		return
	}
	if model == "" {
		model = cli.Model
	}
	s.Store.RecordLLMUsage(model, usage.PromptTokens, usage.CompletionTokens, usage.TotalTokens)
	_ = send(map[string]any{"done": true, "usage": usage})
}

// History limits for one chat turn: the newest messages win, and the final
// message is always kept even when it alone exceeds the budget.
const (
	maxChatTurns = 60
	maxChatRunes = 60000
)

// trimChatHistory keeps the most recent maxTurns messages within maxRunes of
// content, dropping a leading assistant turn so providers that require the
// first message to be from the user still accept the request.
func trimChatHistory(msgs []llm.Message, maxTurns, maxRunes int) []llm.Message {
	if len(msgs) == 0 {
		return msgs
	}
	total := 0
	start := len(msgs)
	for i := len(msgs) - 1; i >= 0; i-- {
		n := utf8.RuneCountInString(msgs[i].Content)
		if start != len(msgs) && (len(msgs)-i > maxTurns || total+n > maxRunes) {
			break
		}
		total += n
		start = i
	}
	out := msgs[start:]
	for len(out) > 1 && strings.EqualFold(out[0].Role, "assistant") {
		out = out[1:]
	}
	return out
}

// adminLLMConfig reads or updates the LLM config (base URL, key, model). The
// values are persisted so a restart restores them; the key is sealed at rest
// and never returned to the console.
func (s *Server) adminLLMConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		resp := map[string]any{"configured": false, "base_url": "", "model": "", "plan_model": "", "key_set": false, "temperature": 0.7}
		if cli := s.getLLM(); cli != nil {
			resp["configured"] = cli.Available()
			resp["base_url"] = cli.BaseURL
			resp["model"] = cli.Model
			resp["key_set"] = cli.Key != ""
			resp["temperature"] = cli.Temperature
		}
		resp["plan_model"] = s.appSettingsSnapshot().LLMPlanModel
		s.writeJSON(w, 200, resp)
		return
	}
	if r.Method != http.MethodPost {
		s.writeJSON(w, 405, map[string]any{"error": "GET or POST"})
		return
	}
	var req struct {
		BaseURL     string   `json:"base_url"`
		Key         string   `json:"key"`
		Model       string   `json:"model"`
		PlanModel   string   `json:"plan_model"`
		Temperature *float64 `json:"temperature"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	cli := s.getLLM()
	baseURL := strings.TrimSpace(req.BaseURL)
	key := strings.TrimSpace(req.Key)
	model := strings.TrimSpace(req.Model)
	planModel := strings.TrimSpace(req.PlanModel)
	if cli != nil {
		if baseURL == "" {
			baseURL = cli.BaseURL
		}
		if key == "" {
			key = cli.Key
		}
		if model == "" {
			model = cli.Model
		}
	}
	if baseURL == "" {
		s.writeJSON(w, 400, map[string]any{"error": "base_url required"})
		return
	}
	if err := llm.ValidateBaseURL(baseURL); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	temp := 0.7
	if cli != nil {
		temp = cli.Temperature
	}
	if req.Temperature != nil {
		if *req.Temperature < 0 || *req.Temperature > 2 {
			s.writeJSON(w, 400, map[string]any{"error": "temperature 必须在 0 到 2 之间"})
			return
		}
		temp = *req.Temperature
	}
	// Persist before swapping so a restart restores the same provider. The key
	// is sealed with the platform secret key; an empty key keeps the stored one.
	if s.Store != nil {
		if err := s.putSetting(settingLLMBaseURL, baseURL); err != nil {
			s.writeJSON(w, 500, map[string]any{"error": "保存 LLM 配置失败: " + err.Error()})
			return
		}
		if err := s.putSetting(settingLLMModel, model); err != nil {
			s.writeJSON(w, 500, map[string]any{"error": "保存 LLM 配置失败: " + err.Error()})
			return
		}
		if err := s.putSetting(settingLLMPlanModel, planModel); err != nil {
			s.writeJSON(w, 500, map[string]any{"error": "保存规划模型失败: " + err.Error()})
			return
		}
		if err := s.putSetting(settingLLMTemperature, strconv.FormatFloat(temp, 'f', -1, 64)); err != nil {
			s.writeJSON(w, 500, map[string]any{"error": "保存 LLM 配置失败: " + err.Error()})
			return
		}
		if key != "" {
			if err := s.putSetting(settingLLMKey, s.Store.EncryptSetting(key)); err != nil {
				s.writeJSON(w, 500, map[string]any{"error": "保存 LLM 配置失败: " + err.Error()})
				return
			}
		}
	}
	client := llm.New(baseURL, key, model)
	client.Temperature = temp
	s.setLLM(client)
	s.writeJSON(w, 200, map[string]any{"configured": true, "base_url": baseURL, "model": model, "plan_model": planModel, "key_set": key != "", "temperature": temp})
}

// adminLLMSecret returns the configured LLM API key for the console eye
// toggle. The key is never part of the normal config response.
func (s *Server) adminLLMSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, 405, map[string]any{"error": "GET only"})
		return
	}
	key := ""
	if cli := s.getLLM(); cli != nil {
		key = cli.Key
	}
	s.log().Info("admin reveal llm key", "ip", s.remoteIP(r))
	s.writeJSON(w, 200, map[string]any{"key": key})
}

// planModel returns the optional planning model: console setting first, then
// the PHISH_LLM_PLAN_MODEL deployment value.
func (s *Server) planModel() string {
	if st := s.appSettingsSnapshot(); strings.TrimSpace(st.LLMPlanModel) != "" {
		return strings.TrimSpace(st.LLMPlanModel)
	}
	if s.Cfg != nil {
		return strings.TrimSpace(s.Cfg.LLMPlanModel)
	}
	return ""
}

// RestoreLLMConfig applies the LLM settings saved from the console after a
// restart. An explicit PHISH_LLM_* deployment value wins per field; the
// built-in default model does not override a model chosen in the console.
func (s *Server) RestoreLLMConfig() {
	if s.Store == nil {
		return
	}
	st := s.appSettingsSnapshot()
	baseURL, model, key := st.LLMBaseURL, st.LLMModel, ""
	if st.LLMKeyEnc != "" {
		key = s.Store.DecryptSetting(st.LLMKeyEnc)
	}
	temp := 0.7
	if st.LLMTemperature != "" {
		if v, err := strconv.ParseFloat(st.LLMTemperature, 64); err == nil && v >= 0 && v <= 2 {
			temp = v
		}
	}
	if cli := s.getLLM(); cli != nil {
		if cli.BaseURL != "" {
			baseURL = cli.BaseURL
		}
		// The launch default (deepseek-flash) must not clobber a saved model.
		if s.Cfg.LLMModelSet || model == "" {
			if cli.Model != "" {
				model = cli.Model
			}
		}
		if cli.Key != "" {
			key = cli.Key
		}
	}
	// An explicit deployment temperature wins whether or not a client exists.
	if s.Cfg.LLMTemperatureSet {
		temp = s.Cfg.LLMTemperature
	}
	if baseURL == "" {
		return
	}
	client := llm.New(baseURL, key, model)
	client.Temperature = temp
	s.setLLM(client)
}

// adminLogs returns recent structured log records for the console log viewer.
func (s *Server) adminLogs(w http.ResponseWriter, r *http.Request) {
	retention := s.appSettingsSnapshot().LogRetentionDays
	level := strings.ToLower(r.URL.Query().Get("level"))
	minRank := 0
	switch level {
	case "warn":
		minRank = 2
	case "error":
		minRank = 3
	}
	limit := int(parseInt(r.URL.Query().Get("limit")))
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}
	offset := int(parseInt(r.URL.Query().Get("offset")))
	if offset < 0 {
		offset = 0
	}
	fetch := offset + limit + 1
	if fetch > 500 {
		fetch = 500
	}
	since := ""
	if retention > 0 {
		since = time.Now().AddDate(0, 0, -retention).UTC().Format(time.RFC3339)
	}

	type row struct {
		ID    int64             `json:"id"`
		Time  string            `json:"time"`
		Level string            `json:"level"`
		Msg   string            `json:"msg"`
		Attrs map[string]string `json:"attrs,omitempty"`
	}
	out := []row{}
	errs, warns := 0, 0
	filtered := []row{}
	if s.Store != nil {
		rows, err := s.Store.LogsSince(since, "", fetch)
		if err != nil {
			s.writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		for _, l := range rows {
			switch l.Level {
			case "ERROR":
				errs++
			case "WARN":
				warns++
			}
			if logRank(l.Level) < minRank {
				continue
			}
			var attrs map[string]string
			_ = json.Unmarshal([]byte(l.Attrs), &attrs)
			if len(attrs) == 0 {
				attrs = nil
			}
			filtered = append(filtered, row{ID: l.ID, Time: l.Time, Level: l.Level, Msg: l.Message, Attrs: attrs})
		}
	} else if s.LogBuffer != nil {
		for _, e := range s.LogBuffer.Entries("", fetch) {
			switch e.Level {
			case "ERROR":
				errs++
			case "WARN":
				warns++
			}
			if logRank(e.Level) < minRank {
				continue
			}
			filtered = append(filtered, row{Time: e.Time, Level: e.Level, Msg: e.Message, Attrs: e.Attrs})
		}
	}
	hasMore := len(filtered) > offset+limit
	start := offset
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	out = filtered[start:end]
	s.writeJSON(w, http.StatusOK, map[string]any{
		"logs": out, "errors": errs, "warns": warns, "retention_days": retention,
		"has_more": hasMore, "offset": offset, "limit": limit,
	})
}

func logRank(level string) int {
	switch level {
	case "ERROR":
		return 3
	case "WARN":
		return 2
	case "INFO":
		return 1
	}
	return 0
}

// adminLogRetention saves how many days of logs to keep and prunes immediately.
func (s *Server) adminLogRetention(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Days int `json:"days"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	if req.Days < 0 || req.Days > 3650 {
		s.writeJSON(w, http.StatusBadRequest, map[string]any{"error": "保留天数需在 0-3650 之间（0 = 永久保留）"})
		return
	}
	if err := s.putSetting(settingLogRetention, strconv.Itoa(req.Days)); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	deleted := int64(0)
	if req.Days > 0 && s.Store != nil {
		cutoff := time.Now().AddDate(0, 0, -req.Days).UTC().Format(time.RFC3339)
		deleted, _ = s.Store.DeleteLogsBefore(cutoff)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "retention_days": req.Days, "deleted": deleted})
}

// adminClearLogs wipes persisted and in-memory logs.
func (s *Server) adminClearLogs(w http.ResponseWriter, r *http.Request) {
	var deleted int64
	if s.Store != nil {
		deleted, _ = s.Store.ClearLogs()
	}
	if s.LogBuffer != nil {
		s.LogBuffer.Clear()
	}
	s.log().Info("application logs cleared", "deleted", deleted)
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": deleted})
}

// pruneLogs enforces the configured retention window.
func (s *Server) pruneLogs(days int) int64 {
	if s.Store == nil || days <= 0 {
		return 0
	}
	cutoff := time.Now().AddDate(0, 0, -days).UTC().Format(time.RFC3339)
	n, _ := s.Store.DeleteLogsBefore(cutoff)
	return n
}

// adminAnalyze returns the platform data snapshot and its text summary.
func (s *Server) adminAnalyze(w http.ResponseWriter, r *http.Request) {
	snap, err := analyze.BuildCached(s.Store, 30*time.Second, s.geoLookup)
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"snapshot": snap, "text": snap.Text()})
}

// adminDeleteProfile removes a sending profile. Campaigns that referenced it
// are detached and fall back to preview-only, which matches deleting a profile
// in the console.
func (s *Server) adminDeleteProfile(w http.ResponseWriter, r *http.Request, id int64) {
	if names, err := s.Store.CampaignsUsingProfile(id); err == nil && len(names) > 0 {
		s.writeJSON(w, 400, map[string]any{"error": "该发件账号仍被活动" + store.ReferencedBy(names) + "使用（含回收站），请先改绑或彻底处理这些活动"})
		return
	}
	if err := s.Store.DeleteSendingProfile(id); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"deleted": id})
}

// adminGroups lists or creates a group.
func (s *Server) adminGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		list, err := s.Store.ListGroups()
		if err != nil {
			s.writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		s.writeJSON(w, 200, map[string]any{"groups": list})
		return
	}
	if r.Method == http.MethodPost {
		var req struct {
			Name    string         `json:"name"`
			Targets []store.Target `json:"targets"`
			CSV     string         `json:"csv"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&req); err != nil {
			s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		if req.Name == "" {
			s.writeJSON(w, 400, map[string]any{"error": "group name required"})
			return
		}
		targets := req.Targets
		if len(targets) == 0 && req.CSV != "" {
			targets = parseTargetCSV(req.CSV)
		}
		id, err := s.Store.CreateGroup(req.Name)
		if err != nil {
			s.writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		n := 0
		if len(targets) > 0 {
			n, err = s.Store.AddTargetsToGroup(id, targets)
			if err != nil {
				s.writeJSON(w, 500, map[string]any{"error": err.Error()})
				return
			}
		}
		s.writeJSON(w, 200, map[string]any{"id": id, "targets_added": n})
		return
	}
	s.writeJSON(w, 405, map[string]any{"error": "GET or POST"})
}

// adminGroupTargets lists or imports targets for one group.
func (s *Server) adminGroupTargets(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method == http.MethodGet {
		targets, err := s.Store.ListGroupTargets(id)
		if err != nil {
			s.writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		s.writeJSON(w, 200, map[string]any{"targets": targets})
		return
	}
	if r.Method == http.MethodPost {
		body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
		var req struct {
			Targets []store.Target `json:"targets"`
			CSV     string         `json:"csv"`
		}
		var targets []store.Target
		if err := json.Unmarshal(body, &req); err == nil && (len(req.Targets) > 0 || req.CSV != "") {
			if len(req.Targets) > 0 {
				targets = req.Targets
			} else {
				targets = parseTargetCSV(req.CSV)
			}
		} else {
			targets = parseTargetCSV(string(body))
		}
		if len(targets) == 0 {
			s.writeJSON(w, 400, map[string]any{"error": "no targets provided"})
			return
		}
		n, err := s.Store.AddTargetsToGroup(id, targets)
		if err != nil {
			s.writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		s.writeJSON(w, 200, map[string]any{"targets_added": n})
		return
	}
	s.writeJSON(w, 405, map[string]any{"error": "GET or POST"})
}

// adminDeleteGroupTarget removes one target from a group.
func (s *Server) adminDeleteGroupTarget(w http.ResponseWriter, r *http.Request, groupID, targetID int64) {
	if err := s.Store.DeleteTarget(groupID, targetID); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"deleted": targetID})
}

// adminProfiles lists or upserts a sending profile.
func (s *Server) adminProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		list, err := s.Store.ListSendingProfiles()
		if err != nil {
			s.writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		s.writeJSON(w, 200, map[string]any{"profiles": list})
		return
	}
	if r.Method == http.MethodPost {
		var p store.SendingProfile
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&p); err != nil {
			s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		if p.InterfaceType == "" {
			p.InterfaceType = "SMTP"
		}
		p.Host = strings.TrimSpace(p.Host)
		p.FromEmail = strings.TrimSpace(p.FromEmail)
		if p.Host == "" {
			s.writeJSON(w, 400, map[string]any{"error": "SMTP host required"})
			return
		}
		if p.Port <= 0 || p.Port > 65535 {
			s.writeJSON(w, 400, map[string]any{"error": "port must be 1-65535"})
			return
		}
		switch p.TLSMode {
		case "", "starttls", "ssl", "none":
		default:
			s.writeJSON(w, 400, map[string]any{"error": "tls_mode must be starttls, ssl or none"})
			return
		}
		if p.Port == 465 && p.TLSMode != "ssl" {
			s.writeJSON(w, 400, map[string]any{"error": "465 端口必须使用 ssl 加密（smtps）"})
			return
		}
		// Editing without re-entering the password keeps the stored one.
		if p.ID > 0 && p.Password == "" {
			if existing, err := s.Store.GetSendingProfile(p.ID); err == nil {
				p.Password = existing.Password
			}
		}
		if p.FromEmail == "" && strings.Contains(p.Username, "@") {
			p.FromEmail = p.Username
		}
		id, err := s.Store.UpsertSendingProfile(p)
		if err != nil {
			s.writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		s.writeJSON(w, 200, map[string]any{"id": id})
		return
	}
	s.writeJSON(w, 405, map[string]any{"error": "GET or POST"})
}

// adminProfileSecret returns the stored SMTP password for one profile. The
// console only calls it when the operator clicks the eye toggle, and every
// reveal is logged.
func (s *Server) adminProfileSecret(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, 405, map[string]any{"error": "GET only"})
		return
	}
	p, err := s.Store.GetSendingProfile(id)
	if err != nil {
		s.notFound(w)
		return
	}
	s.log().Info("admin reveal smtp password", "profile", id, "ip", s.remoteIP(r))
	s.writeJSON(w, 200, map[string]any{"password": p.Password})
}

// adminAddCampaignTargets appends recipients to an existing campaign. It
// accepts either structured targets or a text block (one "email,department"
// per line). Duplicates already in the campaign are skipped.
func (s *Server) adminAddCampaignTargets(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var req struct {
		Targets []store.Target `json:"targets"`
		Emails  string         `json:"emails"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	targets := req.Targets
	if len(targets) == 0 && strings.TrimSpace(req.Emails) != "" {
		for _, line := range strings.FieldsFunc(req.Emails, func(r rune) bool { return r == '\n' || r == '\r' }) {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.FieldsFunc(line, func(r rune) bool {
				return r == ',' || r == '，' || r == '\t' || r == ';' || r == '；'
			})
			if len(parts) == 0 {
				continue
			}
			t := store.Target{Email: strings.TrimSpace(parts[0])}
			if len(parts) > 1 {
				t.Department = strings.TrimSpace(parts[1])
			}
			targets = append(targets, t)
		}
	}
	added, skipped, err := s.Store.AddCampaignTargets(id, targets)
	if err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.log().Info("campaign targets added", "campaign", id, "added", added, "skipped", skipped, "ip", s.remoteIP(r))
	s.writeJSON(w, 200, map[string]any{"added": added, "skipped": skipped})
}
func (s *Server) adminTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		list, err := s.Store.ListTemplates()
		if err != nil {
			s.writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		s.writeJSON(w, 200, map[string]any{"templates": list})
		return
	}
	if r.Method == http.MethodPost {
		var t store.EmailTemplate
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&t); err != nil {
			s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		id, err := s.Store.UpsertTemplate(t)
		if err != nil {
			s.writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		// MySQL returns 0 for an ON DUPLICATE KEY update; resolve the id.
		if id == 0 {
			if list, err := s.Store.ListTemplates(); err == nil {
				for _, item := range list {
					if item.Name == t.Name {
						id = item.ID
						break
					}
				}
			}
		}
		if id > 0 {
			if err := s.Store.SetTemplateDefaultPage(id, t.DefaultLandingPageID); err != nil {
				s.writeJSON(w, 400, map[string]any{"error": err.Error()})
				return
			}
		}
		s.writeJSON(w, 200, map[string]any{"id": id})
		return
	}
	s.writeJSON(w, 405, map[string]any{"error": "GET or POST"})
}

// adminPages lists or creates a template landing page.
func (s *Server) adminPages(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		list, err := s.Store.ListPages()
		if err != nil {
			s.writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		s.writeJSON(w, 200, map[string]any{"pages": list})
		return
	}
	if r.Method == http.MethodPost {
		var p store.LandingPage
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&p); err != nil {
			s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
			return
		}
		p.Kind = "template"
		if p.ContentType == "" {
			p.ContentType = "text/html; charset=utf-8"
		}
		id, err := s.Store.UpsertPage(p, nil)
		if err != nil {
			s.writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		s.writeJSON(w, 200, map[string]any{"id": id})
		return
	}
	s.writeJSON(w, 405, map[string]any{"error": "GET or POST"})
}

// adminImportPage imports an LLM-generated HTML payload as a landing page.
func (s *Server) adminImportPage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string `json:"name"`
		HTML         string `json:"html"`
		ErrorMessage string `json:"error_message"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	body := extractHTML(req.HTML)
	if strings.TrimSpace(body) == "" {
		s.writeJSON(w, 400, map[string]any{"error": "HTML 内容为空"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "AI生成-" + time.Now().Format("20060102-150405")
	}
	id, err := s.Store.UpsertPage(store.LandingPage{
		Name:               name,
		Kind:               "template",
		Body:               body,
		ContentType:        "text/html; charset=utf-8",
		CaptureCredentials: true,
		CapturePasswords:   true,
		ErrorMessage:       strings.TrimSpace(req.ErrorMessage),
	}, nil)
	if err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"id": id, "name": name})
}

// injectHeadScript inserts a script immediately after <head> so it runs before
// the page's own bundles.
func injectHeadScript(doc []byte, js string) []byte {
	lower := bytes.ToLower(doc)
	idx := 0
	if h := bytes.Index(lower, []byte("<head")); h >= 0 {
		if end := bytes.IndexByte(doc[h:], '>'); end >= 0 {
			idx = h + end + 1
		}
	}
	block := []byte(`<script data-hp-hash="1">` + js + `</script>`)
	out := make([]byte, 0, len(doc)+len(block)+1)
	out = append(out, doc[:idx]...)
	out = append(out, block...)
	out = append(out, '\n')
	out = append(out, doc[idx:]...)
	return out
}

// extractHTML pulls the HTML payload out of an LLM reply, stripping markdown
// code fences (```html ... ```) when present.
func extractHTML(s string) string {
	lower := strings.ToLower(s)
	if i := strings.Index(lower, "```html"); i >= 0 {
		rest := s[i+len("```html"):]
		if j := strings.Index(rest, "```"); j >= 0 {
			return strings.TrimSpace(rest[:j])
		}
		return strings.TrimSpace(rest)
	}
	if i := strings.Index(lower, "```"); i >= 0 {
		rest := s[i+3:]
		if nl := strings.Index(rest, "\n"); nl >= 0 {
			rest = rest[nl+1:]
		}
		if j := strings.Index(rest, "```"); j >= 0 {
			return strings.TrimSpace(rest[:j])
		}
	}
	return strings.TrimSpace(s)
}

// adminImportTemplate imports an LLM-generated email as a template.
func (s *Server) adminImportTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Subject string `json:"subject"`
		HTML    string `json:"html"`
		Text    string `json:"text"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	body := extractHTML(req.HTML)
	if strings.TrimSpace(body) == "" {
		s.writeJSON(w, 400, map[string]any{"error": "HTML 内容为空"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "AI生成-" + time.Now().Format("20060102-150405")
	}
	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		subject = extractSubject(req.HTML)
	}
	text := strings.TrimSpace(req.Text)
	if text == "" {
		text = extractText(req.HTML)
	}
	id, err := s.Store.UpsertTemplate(store.EmailTemplate{Name: name, Subject: subject, HTML: body, Text: text})
	if err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"id": id, "name": name})
}

// extractSubject pulls an email subject out of an LLM reply ("主题：xxx" /
// "Subject: xxx" line, or a <title>).
func extractSubject(s string) string {
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		for _, prefix := range []string{"主题：", "主题:", "Subject:", "subject:", "SUBJECT:"} {
			if strings.HasPrefix(t, prefix) {
				return strings.TrimSpace(strings.TrimPrefix(t, prefix))
			}
		}
	}
	if i := strings.Index(strings.ToLower(s), "<title>"); i >= 0 {
		rest := s[i+len("<title>"):]
		if j := strings.Index(strings.ToLower(rest), "</title>"); j >= 0 {
			return strings.TrimSpace(rest[:j])
		}
	}
	return ""
}

// extractText pulls a plain-text body out of an LLM reply's ```text fence.
func extractText(s string) string {
	if i := strings.Index(strings.ToLower(s), "```text"); i >= 0 {
		rest := s[i+len("```text"):]
		if j := strings.Index(rest, "```"); j >= 0 {
			return strings.TrimSpace(rest[:j])
		}
		return strings.TrimSpace(rest)
	}
	return ""
}

// adminClone fetches an external site and stores it as a cloned landing page.
func (s *Server) adminClone(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name               string `json:"name"`
		URL                string `json:"url"`
		CaptureCredentials bool   `json:"capture_credentials"`
		CapturePasswords   bool   `json:"capture_passwords"`
		RedirectURL        string `json:"redirect_url"`
		// ErrorMessage is the page-language "wrong password" copy.
		ErrorMessage string `json:"error_message"`
		StaticForm   bool   `json:"static_form"`
		// Proxy stores a live reverse-proxy landing page instead of a snapshot.
		// It is the reliable choice for SPAs whose login flow needs live API
		// responses; the upstream must stay reachable while the campaign runs.
		Proxy bool `json:"proxy"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	req.Name = strings.TrimSpace(req.Name)
	if req.URL == "" {
		s.writeJSON(w, 400, map[string]any{"error": "url required"})
		return
	}
	if req.Name == "" {
		req.Name = "clone-" + req.URL
	}
	if u, err := url.Parse(req.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		s.writeJSON(w, 400, map[string]any{"error": "url must be http(s)"})
		return
	}
	if req.Proxy {
		if s.Cfg.CloneDenyPrivate {
			if u, err := url.Parse(req.URL); err == nil && clone.IsPrivateHost(u.Host) {
				s.writeJSON(w, 400, map[string]any{"error": "拒绝代理内网地址（已开启 -clone-deny-private）"})
				return
			}
		}
		finalURL, status, err := s.proxyProbe(req.URL)
		if err != nil {
			s.writeJSON(w, 400, map[string]any{"error": "代理目标不可达或不是页面: " + err.Error()})
			return
		}
		id, err := s.Store.UpsertPage(store.LandingPage{
			Name:               req.Name,
			Kind:               "proxy",
			SourceURL:          finalURL,
			ContentType:        "text/html; charset=utf-8",
			CaptureCredentials: req.CaptureCredentials,
			CapturePasswords:   req.CapturePasswords,
			RedirectURL:        req.RedirectURL,
			ErrorMessage:       strings.TrimSpace(req.ErrorMessage),
		}, nil)
		if err != nil {
			s.writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		s.writeJSON(w, 200, map[string]any{
			"id": id, "name": req.Name, "kind": "proxy",
			"source_url": finalURL, "status": status, "method": "proxy",
		})
		return
	}
	opts := clone.Options{
		URL:          req.URL,
		BaseURL:      s.publicURL(),
		MirrorAssets: true,
		SPAShim:      true,
		AssetPrefix:  "/__assets__/",
		FormAction:   "/__submit__",
		Timeout:      30 * time.Second,
		MaxBodyBytes: 16 << 20,
		DenyPrivate:  s.Cfg.CloneDenyPrivate,
		StaticForm:   req.StaticForm,
		CaptureNet:   !req.StaticForm, // static-form clones drop JS, so the API map is useless
	}
	// Prefer a headless-browser render (SPA/dynamic sites), then fall back to
	// the static cloner when no browser is available.
	res, err := clone.CloneWithBrowser(opts)
	method := "browser"
	if err != nil {
		res, err = clone.Clone(opts)
		method = "static"
	}
	if err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "clone failed: " + err.Error()})
		return
	}
	assets := make([]store.PageAsset, 0, len(res.Assets))
	for _, a := range res.Assets {
		assets = append(assets, store.PageAsset{Path: a.Path, ContentType: a.ContentType, Body: a.Body})
	}
	ct := res.ContentType
	if ct == "" {
		ct = "text/html; charset=utf-8"
	}
	body := res.Body
	// SPA clones often render at a hash route (for example an OAuth context
	// URL). Served under /p/<id>/ or /l/<rid>/ the hash is gone, so the router
	// matches nothing and the page looks blank. Re-apply the final fragment
	// before the app's own scripts run.
	if u, err := url.Parse(res.FinalURL); err == nil && u.Fragment != "" {
		body = injectHeadScript(body, `try{if(!location.hash)location.hash=`+strconv.Quote(u.Fragment)+`}catch(e){}`)
	}
	id, err := s.Store.UpsertPage(store.LandingPage{
		Name:               req.Name,
		Kind:               "clone",
		SourceURL:          req.URL,
		Body:               string(body),
		ContentType:        ct,
		CaptureCredentials: req.CaptureCredentials,
		CapturePasswords:   req.CapturePasswords,
		RedirectURL:        req.RedirectURL,
		ErrorMessage:       strings.TrimSpace(req.ErrorMessage),
	}, assets)
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{
		"id":           id,
		"name":         req.Name,
		"final_url":    res.FinalURL,
		"spa":          res.SPA,
		"assets":       len(assets),
		"body_bytes":   len(res.Body),
		"method":       method,
		"forms":        res.FormCount,
		"passwords":    res.PasswordCount,
		"captured_api": res.CapturedAPI,
	})
}

// adminSend generates the phishing emails for a campaign and, when the
// campaign's sending profile is configured, sends them. It always returns the
// rendered previews.
// sendOutcome reports the result of one campaign send.
type sendOutcome struct {
	Sent     int
	Failed   int
	Total    int
	Seeds    int
	SMTP     bool
	DryRun   bool
	Previews []map[string]any
	// Delivery diagnostics: failures by kind, recipients that needed a retry,
	// and what the circuit breaker stopped.
	FailedKinds   map[string]int `json:"failed_kinds,omitempty"`
	Retried       int            `json:"retried,omitempty"`
	Skipped       int            `json:"skipped,omitempty"`
	Suppressed    int            `json:"suppressed,omitempty"`
	StoppedReason string         `json:"stopped_reason,omitempty"`
}

// sendBundle is one email template plus its attachment bytes, loaded once per
// send. A/B campaigns hold one bundle per variant.
type sendBundle struct {
	tmpl store.EmailTemplate
	atts []email.Attachment
}

// sendCampaignEmail renders and sends a campaign's pending emails, optionally
// batching (batchSize emails per batch, batchDelaySec seconds between batches).
// With dryRun it only renders previews and never talks to SMTP. It returns
// counts and up to 5 previews for display.
// recordSendLedger writes one immutable delivery record. Unlike results and
// campaigns, the ledger survives campaign deletion.
func (s *Server) recordSendLedger(camp store.Campaign, res store.Result, templateID int64, subject string, profile store.SendingProfile, status, kind, detail, messageID string) {
	if s.Store == nil {
		return
	}
	err := s.Store.RecordSendLedger(store.SendLedgerEntry{
		CampaignID: camp.ID, CampaignName: camp.Name, TemplateID: templateID,
		Email: res.Email, Subject: subject, FromEmail: profile.FromEmail,
		Variant: res.Variant, Status: status, FailureKind: kind, Detail: detail,
		MessageID: messageID,
	})
	if err != nil {
		s.log().Warn("record send ledger", "err", err)
	}
}

func (s *Server) sendCampaignEmail(campID int64, batchSize, batchDelaySec int, dryRun bool) (sendOutcome, error) {
	out := sendOutcome{FailedKinds: map[string]int{}}
	camp, err := s.Store.GetCampaign(campID)
	if err != nil {
		return out, err
	}
	if camp.DeletedAt != "" {
		return out, fmt.Errorf("活动已删除（在回收站），不能发送")
	}
	loadBundle := func(templateID int64) (*sendBundle, error) {
		t, terr := s.Store.GetTemplate(templateID)
		if terr != nil {
			return nil, terr
		}
		attachments, aerr := s.Store.TemplateAttachmentsWithBody(t.ID)
		if aerr != nil {
			return nil, fmt.Errorf("load template attachments: %w", aerr)
		}
		b := &sendBundle{tmpl: t, atts: make([]email.Attachment, 0, len(attachments))}
		for _, a := range attachments {
			b.atts = append(b.atts, email.Attachment{Name: a.Name, ContentType: a.ContentType, Body: a.Body})
		}
		return b, nil
	}
	bundleA, err := loadBundle(camp.EmailTemplateID)
	if err != nil {
		return out, fmt.Errorf("email template missing: %w", err)
	}
	var bundleB *sendBundle
	if camp.EmailTemplateBID > 0 && camp.EmailTemplateBID != camp.EmailTemplateID {
		bundleB, err = loadBundle(camp.EmailTemplateBID)
		if err != nil {
			return out, fmt.Errorf("B 模板不可用: %w", err)
		}
	}
	results, err := s.Store.ListResults(campID)
	if err != nil {
		return out, err
	}
	profile := store.SendingProfile{}
	if camp.SendingProfileID > 0 {
		profile, _ = s.Store.GetSendingProfile(camp.SendingProfileID)
	}
	canSend := profile.Host != "" && !dryRun
	out.SMTP = profile.Host != ""
	out.DryRun = dryRun
	out.Total = len(results)
	suppressed, _ := s.Store.SuppressionSet()
	pendingResults := make([]store.Result, 0, len(results))
	for _, res := range results {
		if res.Sent || res.Unsubscribed {
			continue
		}
		if suppressed[strings.ToLower(strings.TrimSpace(res.Email))] {
			out.Suppressed++
			continue
		}
		pendingResults = append(pendingResults, res)
	}
	pending := len(pendingResults)
	// Guard against an accidental mass send (wrong group, duplicated campaign).
	if canSend && s.Cfg.MaxSendTargets > 0 && pending > s.Cfg.MaxSendTargets {
		return out, fmt.Errorf("待发送 %d 人，超过单次上限 %d 人；请分批发送或调整 -max-send-targets", pending, s.Cfg.MaxSendTargets)
	}
	policy := sendPolicyFromEnv()
	consecFail := 0
	inBatch := 0
	for i, res := range pendingResults {
		// A dry run or an SMTP-less preview only needs the first five renders.
		if !canSend && len(out.Previews) >= 5 {
			continue
		}
		landing, pixel, report, unsubscribe := s.trackingURLs(res.Rid)
		b := bundleA
		if res.Variant == "B" && bundleB != nil {
			b = bundleB
		}
		rendered, rerr := email.Render(b.tmpl.Subject, b.tmpl.HTML, b.tmpl.Text, email.Context{
			FirstName:      res.FirstName,
			LastName:       res.LastName,
			Email:          res.Email,
			Position:       res.Position,
			TrackingURL:    landing,
			TrackingPixel:  pixel,
			ReportURL:      report,
			UnsubscribeURL: unsubscribe,
			FromName:       profile.FromName,
			FromEmail:      profile.FromEmail,
		})
		if rerr != nil {
			out.Failed++
			out.FailedKinds[string(email.FailRender)]++
			s.recordSendLedger(camp, res, b.tmpl.ID, b.tmpl.Subject, profile, "failed", string(email.FailRender), rerr.Error(), "")
			s.recordSendFailure(campID, res.ID, res.Email, string(email.FailRender), rerr.Error(), 1)
			consecFail++
			if policy.trips(email.Failure{Kind: email.FailRender}, consecFail) {
				out.StoppedReason = breakerReason(email.Failure{Kind: email.FailRender}, consecFail)
				out.Skipped = len(pendingResults) - i - 1
				break
			}
			continue
		}
		rendered.HTML = email.PrepareHTML(rendered.HTML)
		if strings.TrimSpace(rendered.Text) == "" {
			rendered.Text = email.HTMLToText(rendered.HTML)
		}
		if len(out.Previews) < 5 {
			out.Previews = append(out.Previews, map[string]any{
				"email":   res.Email,
				"variant": res.Variant,
				"subject": rendered.Subject,
				"html":    rendered.HTML,
				"text":    rendered.Text,
			})
		}
		if canSend {
			msg, berr := email.Build(email.Message{
				From:        email.FromDisplay(profile.FromName, profile.FromEmail),
				To:          res.Email,
				Subject:     rendered.Subject,
				HTML:        rendered.HTML,
				Text:        rendered.Text,
				Attachments: b.atts,
			})
			if berr != nil {
				out.Failed++
				out.FailedKinds[string(email.FailBuild)]++
				s.recordSendLedger(camp, res, b.tmpl.ID, rendered.Subject, profile, "failed", string(email.FailBuild), berr.Error(), "")
				s.recordSendFailure(campID, res.ID, res.Email, string(email.FailBuild), berr.Error(), 1)
				consecFail++
				if policy.trips(email.Failure{Kind: email.FailBuild}, consecFail) {
					out.StoppedReason = breakerReason(email.Failure{Kind: email.FailBuild}, consecFail)
					out.Skipped = len(pendingResults) - i - 1
					break
				}
				continue
			}
			cfg := email.SMTPConfig{
				Host: profile.Host, Port: profile.Port, User: profile.Username,
				Pass: profile.Password, TLSMode: profile.TLSMode, From: profile.FromEmail,
				IgnoreCert: profile.IgnoreCert,
			}
			fail, attempts := s.deliver(policy, cfg, msg, res.Email)
			if fail.Kind != "" {
				s.log().Error("smtp send", "to", res.Email, "kind", fail.Kind, "code", fail.Code,
					"attempts", attempts, "err", fail.Message)
				out.Failed++
				out.FailedKinds[string(fail.Kind)]++
				if attempts > 1 {
					out.Retried++
				}
				s.recordSendLedger(camp, res, b.tmpl.ID, rendered.Subject, profile, "failed", string(fail.Kind), fail.Message, email.MessageID(msg))
				s.recordSendFailure(campID, res.ID, res.Email, string(fail.Kind), fail.Message, attempts)
				consecFail++
				if policy.trips(fail, consecFail) {
					out.StoppedReason = breakerReason(fail, consecFail)
					out.Skipped = len(pendingResults) - i - 1
					s.log().Warn("send paused by circuit breaker", "campaign", campID,
						"kind", fail.Kind, "consecutive", consecFail, "skipped", out.Skipped)
					break
				}
				continue
			}
			_ = s.Store.ClearSendFailure(campID, res.ID)
			s.Store.MarkSent(res.ID)
			s.recordSendLedger(camp, res, b.tmpl.ID, rendered.Subject, profile, "sent", "", "", email.MessageID(msg))
			out.Sent++
			consecFail = 0
			inBatch++
			// Batch pacing: sleep between batches.
			if batchSize > 0 && inBatch%batchSize == 0 && batchDelaySec > 0 {
				time.Sleep(time.Duration(batchDelaySec) * time.Second)
			}
			// Outbound rate limit (emails/second).
			if s.Cfg.SMTPRatePerSec > 0 {
				time.Sleep(time.Duration(float64(time.Second) / s.Cfg.SMTPRatePerSec))
			}
		}
	}
	// Seed delivery: send the A template once to each operator-supplied seed
	// address for placement/spam-filter checks. Seed sends are recorded in the
	// ledger with variant "seed".
	if canSend {
		for _, seed := range splitSeedEmails(camp.SeedEmails) {
			if suppressed[strings.ToLower(strings.TrimSpace(seed))] {
				out.Suppressed++
				continue
			}
			seedRes := store.Result{Email: seed, Variant: "seed"}
			rendered, rerr := email.Render(bundleA.tmpl.Subject, bundleA.tmpl.HTML, bundleA.tmpl.Text, email.Context{
				FirstName: "Seed", Email: seed, FromName: profile.FromName, FromEmail: profile.FromEmail,
			})
			if rerr != nil {
				out.Failed++
				out.FailedKinds[string(email.FailRender)]++
				s.recordSendLedger(camp, seedRes, bundleA.tmpl.ID, bundleA.tmpl.Subject, profile, "failed", string(email.FailRender), rerr.Error(), "")
				s.recordSendFailure(campID, 0, seed, string(email.FailRender), rerr.Error(), 1)
				continue
			}
			rendered.HTML = email.PrepareHTML(rendered.HTML)
			if strings.TrimSpace(rendered.Text) == "" {
				rendered.Text = email.HTMLToText(rendered.HTML)
			}
			msg, berr := email.Build(email.Message{
				From:        email.FromDisplay(profile.FromName, profile.FromEmail),
				To:          seed,
				Subject:     rendered.Subject,
				HTML:        rendered.HTML,
				Text:        rendered.Text,
				Attachments: bundleA.atts,
			})
			if berr != nil {
				out.Failed++
				out.FailedKinds[string(email.FailBuild)]++
				s.recordSendLedger(camp, seedRes, bundleA.tmpl.ID, rendered.Subject, profile, "failed", string(email.FailBuild), berr.Error(), "")
				s.recordSendFailure(campID, 0, seed, string(email.FailBuild), berr.Error(), 1)
				continue
			}
			cfg := email.SMTPConfig{
				Host: profile.Host, Port: profile.Port, User: profile.Username,
				Pass: profile.Password, TLSMode: profile.TLSMode, From: profile.FromEmail,
				IgnoreCert: profile.IgnoreCert,
			}
			fail, attempts := s.deliver(policy, cfg, msg, seed)
			if fail.Kind != "" {
				s.log().Error("smtp seed send", "to", seed, "kind", fail.Kind,
					"code", fail.Code, "attempts", attempts, "err", fail.Message)
				out.Failed++
				out.FailedKinds[string(fail.Kind)]++
				if attempts > 1 {
					out.Retried++
				}
				s.recordSendLedger(camp, seedRes, bundleA.tmpl.ID, rendered.Subject, profile, "failed", string(fail.Kind), fail.Message, email.MessageID(msg))
				s.recordSendFailure(campID, 0, seed, string(fail.Kind), fail.Message, attempts)
				continue
			}
			s.recordSendLedger(camp, seedRes, bundleA.tmpl.ID, rendered.Subject, profile, "sent", "", "", email.MessageID(msg))
			out.Seeds++
		}
	}
	if out.StoppedReason != "" {
		s.notifyAlert("send_breaker", map[string]any{
			"campaign": camp.Name, "reason": out.StoppedReason,
			"sent": out.Sent, "failed": out.Failed, "skipped": out.Skipped,
		})
	}
	return out, nil
}

// invalidSeedList returns seed entries that are not usable email addresses.
func invalidSeedList(list string) []string {
	fields := strings.FieldsFunc(list, func(r rune) bool {
		return r == ',' || r == ';' || r == 10 || r == 13 || r == ' ' || r == 9
	})
	var bad []string
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if strings.Count(f, "@") != 1 || strings.ContainsAny(f, "<> ") {
			bad = append(bad, f)
		}
	}
	return bad
}

// splitSeedEmails parses a comma/space/newline separated seed list.
func splitSeedEmails(list string) []string {
	fields := strings.FieldsFunc(list, func(r rune) bool {
		return r == ',' || r == ';' || r == 10 || r == 13 || r == ' ' || r == 9
	})
	seen := map[string]bool{}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if !strings.Contains(f, "@") || strings.ContainsAny(f, "<>") || seen[strings.ToLower(f)] {
			continue
		}
		seen[strings.ToLower(f)] = true
		out = append(out, f)
	}
	return out
}

// RunScheduler periodically dispatches due send jobs and sends them in the
// background. It is intended to run as a goroutine for the process lifetime.
func (s *Server) RunScheduler() {
	_ = s.Store.ResetRunningSendJobs()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.dispatchDueSends()
		s.maybeAutoPollBounces()
	}
}

func (s *Server) dispatchDueSends() {
	nowStr := time.Now().UTC().Format(time.RFC3339Nano)
	jobs, err := s.Store.DueSendJobs(nowStr)
	if err != nil {
		s.log().Error("due send jobs", "err", err)
		return
	}
	for _, job := range jobs {
		if err := s.Store.MarkSendJobRunning(job.ID); err != nil {
			continue
		}
		go s.runSendJob(job)
	}
}

func (s *Server) runSendJob(job store.SendJob) {
	out, err := s.sendCampaignEmail(job.CampaignID, job.BatchSize, job.BatchDelaySec, false)
	status := "done"
	if err != nil {
		status = "failed"
		s.log().Error("scheduled send", "job", job.ID, "err", err)
	}
	if out.StoppedReason != "" {
		status = "paused"
		s.log().Warn("scheduled send paused", "job", job.ID, "campaign", job.CampaignID,
			"reason", out.StoppedReason, "sent", out.Sent, "failed", out.Failed, "skipped", out.Skipped)
	}
	if ferr := s.Store.FinishSendJob(job.ID, status, out.Sent, out.Failed); ferr != nil {
		s.log().Error("finish send job", "job", job.ID, "err", ferr)
	}
}

// adminResend resends a campaign. mode=all clears the sent flags first; the
// default (unsent) only covers targets that have not been sent yet.
func (s *Server) adminResend(w http.ResponseWriter, r *http.Request, id int64) {
	var req struct {
		Mode string `json:"mode"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req)
	if req.Mode == "all" {
		if err := s.Store.ResetCampaignSent(id); err != nil {
			s.writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
	}
	out, err := s.sendCampaignEmail(id, 0, 0, false)
	if err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{
		"targets":        out.Total,
		"sent":           out.Sent,
		"failed":         out.Failed,
		"smtp":           out.SMTP,
		"mode":           req.Mode,
		"failed_kinds":   out.FailedKinds,
		"retried":        out.Retried,
		"skipped":        out.Skipped,
		"suppressed":     out.Suppressed,
		"stopped_reason": out.StoppedReason,
	})
}

func (s *Server) adminSend(w http.ResponseWriter, r *http.Request, id int64) {
	var req struct {
		DryRun bool `json:"dry_run"`
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	out, err := s.sendCampaignEmail(id, 0, 0, req.DryRun)
	if err != nil {
		s.log().Error("admin send failed", "campaign", id, "dry_run", req.DryRun, "ip", s.remoteIP(r), "err", err)
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if req.DryRun {
		s.log().Info("admin dry run", "campaign", id, "ip", s.remoteIP(r), "targets", out.Total)
	} else {
		s.log().Info("admin send", "campaign", id, "ip", s.remoteIP(r),
			"targets", out.Total, "sent", out.Sent, "failed", out.Failed, "seeds", out.Seeds)
	}
	s.writeJSON(w, 200, map[string]any{
		"targets":        out.Total,
		"sent":           out.Sent,
		"failed":         out.Failed,
		"smtp":           out.SMTP,
		"dry_run":        out.DryRun,
		"previews":       out.Previews,
		"failed_kinds":   out.FailedKinds,
		"retried":        out.Retried,
		"skipped":        out.Skipped,
		"suppressed":     out.Suppressed,
		"stopped_reason": out.StoppedReason,
	})
}

// adminScheduleSend queues a scheduled (optionally batched) campaign send.
// An empty scheduled_at means "send now".
func (s *Server) adminScheduleSend(w http.ResponseWriter, r *http.Request, id int64) {
	var req struct {
		ScheduledAt   string `json:"scheduled_at"`
		BatchSize     int    `json:"batch_size"`
		BatchDelaySec int    `json:"batch_delay_sec"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json: " + err.Error()})
		return
	}
	if req.BatchSize < 0 || req.BatchSize > 100000 {
		s.writeJSON(w, 400, map[string]any{"error": "batch_size 需在 0–100000 之间"})
		return
	}
	// A large delay would overflow the duration conversion in the send loop.
	if req.BatchDelaySec < 0 || req.BatchDelaySec > 86400 {
		s.writeJSON(w, 400, map[string]any{"error": "batch_delay_sec 需在 0–86400 之间"})
		return
	}
	if camp, err := s.Store.GetCampaign(id); err != nil || camp.DeletedAt != "" {
		s.notFound(w)
		return
	}
	now := time.Now()
	nowStr := now.UTC().Format(time.RFC3339Nano)
	scheduledAt := nowStr
	if raw := strings.TrimSpace(req.ScheduledAt); raw != "" {
		// Accept RFC3339 (the console sends +08:00) or a naive wall-clock
		// string, which is interpreted as Beijing time.
		cst := time.FixedZone("CST", 8*3600)
		t, perr := time.Parse(time.RFC3339, raw)
		if perr != nil {
			t, perr = time.ParseInLocation("2006-01-02T15:04:05", raw, cst)
		}
		if perr != nil {
			s.writeJSON(w, 400, map[string]any{"error": "scheduled_at 需为 RFC3339 时间，或 yyyy-mm-ddThh:mm:ss（按北京时间）"})
			return
		}
		if t.After(now) {
			scheduledAt = t.UTC().Format(time.RFC3339Nano)
		}
	}
	jobID, err := s.Store.CreateSendJob(id, scheduledAt, req.BatchSize, req.BatchDelaySec)
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	// Dispatch immediately when the send is due now.
	if scheduledAt == nowStr {
		if err := s.Store.MarkSendJobRunning(jobID); err == nil {
			go s.runSendJob(store.SendJob{ID: jobID, CampaignID: id, BatchSize: req.BatchSize, BatchDelaySec: req.BatchDelaySec})
		}
	}
	s.writeJSON(w, 200, map[string]any{"job_id": jobID, "scheduled_at": scheduledAt})
}

// adminPurge deletes captured submissions and events older than N days. It
// requires an explicit confirm flag so a stray API call cannot wipe data.
func (s *Server) adminPurge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Days    int  `json:"days"`
		Confirm bool `json:"confirm"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	if !req.Confirm {
		s.writeJSON(w, 400, map[string]any{"error": "confirm=true required"})
		return
	}
	if req.Days <= 0 || req.Days > 3650 {
		s.writeJSON(w, 400, map[string]any{"error": "days must be 1-3650"})
		return
	}
	cutoff := time.Now().AddDate(0, 0, -req.Days)
	subs, events, err := s.Store.PurgeOlderThan(cutoff)
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.log().Info("manual retention purge", "days", req.Days, "submissions", subs, "events", events)
	s.writeJSON(w, 200, map[string]any{
		"submissions": subs,
		"events":      events,
		"cutoff":      cutoff.UTC().Format(time.RFC3339),
	})
}

// adminJobs lists send jobs.
func (s *Server) adminJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.Store.ListSendJobs()
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"jobs": jobs})
}

// adminCancelJob cancels a still-pending send job.
func (s *Server) adminCancelJob(w http.ResponseWriter, r *http.Request, id int64) {
	if err := s.Store.CancelSendJob(id); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"cancelled": id})
}

// adminExport streams a CSV of results + captured submissions.
func (s *Server) adminExport(w http.ResponseWriter, r *http.Request, id int64) {
	if _, err := s.Store.GetCampaign(id); err != nil {
		s.notFound(w)
		return
	}
	results, _ := s.Store.ListResults(id)
	subs, _ := s.Store.ListSubmissions(id)
	s.enrichSubmissions(subs)

	// Join submissions onto results by result id for a single flat CSV.
	subByResult := map[int64][]store.Submission{}
	for _, sub := range subs {
		subByResult[sub.ResultID] = append(subByResult[sub.ResultID], sub)
	}
	fieldNames := map[string]bool{}
	for _, sub := range subs {
		for k := range sub.Fields {
			fieldNames[k] = true
		}
	}
	fieldCols := sortedStringSet(fieldNames)

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="campaign-%d-results.csv"`, id))
	// A UTF-8 BOM makes Excel/WPS read Chinese names and fields correctly.
	_, _ = w.Write([]byte("\xEF\xBB\xBF"))
	wr := csv.NewWriter(w)

	header := []string{"email", "first_name", "last_name", "position", "department", "sent", "opened", "clicked", "submitted", "reported", "submitted_at", "username", "password", "ip", "country", "org", "user_agent"}
	header = append(header, fieldCols...)
	sanitizeCSVRow(header)
	_ = wr.Write(header)

	for _, res := range results {
		subsFor := subByResult[res.ID]
		if len(subsFor) == 0 {
			country, org := s.geoLabels(res.IP)
			row := []string{res.Email, res.FirstName, res.LastName, res.Position, res.Department,
				boolStr(res.Sent), boolStr(res.Opened), boolStr(res.Clicked), boolStr(res.Submitted), boolStr(res.Reported),
				"", "", "", res.IP, country, org, res.UserAgent}
			row = append(row, emptyCols(len(fieldCols))...)
			sanitizeCSVRow(row)
			_ = wr.Write(row)
			continue
		}
		for _, sub := range subsFor {
			row := []string{res.Email, res.FirstName, res.LastName, res.Position, res.Department,
				boolStr(res.Sent), boolStr(res.Opened), boolStr(res.Clicked), boolStr(res.Submitted), boolStr(res.Reported),
				sub.TS, sub.Username, s.mask(sub.Password), sub.IP, sub.Country, sub.Org, sub.UserAgent}
			for _, f := range fieldCols {
				row = append(row, joinValues(sub.Fields[f]))
			}
			sanitizeCSVRow(row)
			_ = wr.Write(row)
		}
	}
	wr.Flush()
}

// sanitizeCSVRow neutralises spreadsheet formula injection. Captured form
// values are attacker-controlled; a cell beginning with = + - @ (or a control
// character) can execute DDE/commands when an operator opens the export in
// Excel or LibreOffice. Prefixing with a single quote forces text.
func sanitizeCSVRow(row []string) {
	for i, v := range row {
		trimmed := strings.TrimLeft(v, " \t\r")
		if trimmed == "" {
			continue
		}
		if strings.IndexByte("=+-@", trimmed[0]) >= 0 {
			row[i] = "'" + v
		}
	}
}

func emptyCols(n int) []string {
	out := make([]string, n)
	return out
}

func sortedStringSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func joinValues(vs []string) string {
	return strings.Join(vs, " | ")
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func parseTargetCSV(text string) []store.Target {
	// Excel exports may carry a UTF-8 BOM, CRLF or tabs/semicolons.
	text = strings.TrimPrefix(text, "\ufeff")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	comma := ','
	firstLine := text
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		firstLine = text[:i]
	}
	switch {
	case strings.Contains(firstLine, "\t") && !strings.Contains(firstLine, ","):
		comma = '\t'
	case strings.Contains(firstLine, ";") && !strings.Contains(firstLine, ","):
		comma = ';'
	}
	rd := csv.NewReader(strings.NewReader(text))
	rd.Comma = comma
	rd.FieldsPerRecord = -1
	rows, err := rd.ReadAll()
	if err != nil {
		return nil
	}
	if len(rows) == 0 {
		return nil
	}
	canonical := func(h string) string {
		switch strings.ToLower(strings.TrimSpace(h)) {
		case "email", "e-mail", "mail", "邮箱", "邮箱地址", "邮件":
			return "email"
		case "first_name", "firstname", "first name", "名", "名字", "姓名":
			return "first_name"
		case "last_name", "lastname", "last name", "姓", "姓氏":
			return "last_name"
		case "position", "职位", "岗位", "职务":
			return "position"
		case "department", "dept", "部门", "所属部门", "事业部", "组织":
			return "department"
		}
		return strings.ToLower(strings.TrimSpace(h))
	}
	header := map[string]int{}
	for i, h := range rows[0] {
		header[canonical(h)] = i
	}
	_, hasHeader := header["email"]
	col := func(name string, row []string) string {
		if i, ok := header[name]; ok && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}
	start := 0
	if hasHeader {
		start = 1
	}
	var out []store.Target
	for _, row := range rows[start:] {
		if hasHeader {
			email := col("email", row)
			if email == "" {
				continue
			}
			out = append(out, store.Target{
				Email:      email,
				FirstName:  col("first_name", row),
				LastName:   col("last_name", row),
				Position:   col("position", row),
				Department: col("department", row),
			})
		} else {
			if len(row) == 0 || strings.TrimSpace(row[0]) == "" {
				continue
			}
			t := store.Target{Email: strings.TrimSpace(row[0])}
			if len(row) > 1 {
				t.FirstName = strings.TrimSpace(row[1])
			}
			if len(row) > 2 {
				t.LastName = strings.TrimSpace(row[2])
			}
			if len(row) > 3 {
				t.Position = strings.TrimSpace(row[3])
			}
			if len(row) > 4 {
				t.Department = strings.TrimSpace(row[4])
			}
			out = append(out, t)
		}
	}
	return out
}

// adminBulkDeleteSubmissions removes selected submission rows of a campaign.
func (s *Server) adminBulkDeleteSubmissions(w http.ResponseWriter, r *http.Request, campaignID int64) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.writeJSON(w, 400, map[string]any{"error": "invalid json"})
		return
	}
	n, err := s.Store.DeleteSubmissions(campaignID, req.IDs)
	if err != nil {
		s.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.log().Info("submissions bulk deleted", "campaign", campaignID, "deleted", n, "ip", s.remoteIP(r))
	s.writeJSON(w, 200, map[string]any{"deleted": n})
}

// adminLLMModels fetches the model ids supported by the configured API key.
func (s *Server) adminLLMModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, 405, map[string]any{"error": "GET only"})
		return
	}
	cli := s.getLLM()
	if cli == nil || !cli.Available() {
		s.writeJSON(w, 400, map[string]any{"error": "LLM 未配置 Base URL"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	models, err := cli.RefreshModels(ctx)
	if err != nil {
		s.writeJSON(w, 502, map[string]any{"error": "获取模型失败: " + err.Error()})
		return
	}
	s.writeJSON(w, 200, map[string]any{"models": models})
}
