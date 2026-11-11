package web

// Dangerous-operation tiering. Read-only calls run freely; writes that create
// new objects run freely; operations that overwrite an existing object by name
// are parked as pending actions and only execute after the operator approves
// them in the console. Sending already has its own two-phase confirmation.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"phishsim/internal/core/store"
	"phishsim/internal/features/llm"
)

// pendingAction is one overwrite the assistant prepared and the operator must
// approve. Args holds the original tool arguments so approval replays the exact
// same call rather than a model-reconstructed one.
type pendingAction struct {
	ID        string    `json:"id"`
	SessionID int64     `json:"-"`
	Tool      string    `json:"tool"`
	Args      string    `json:"-"`
	Kind      string    `json:"kind"` // email_template | landing_page | sending_profile
	Name      string    `json:"name"`
	Summary   string    `json:"summary"`
	Expires   time.Time `json:"-"`
}

type confirmedKey struct{}

// withConfirmed marks a replayed call as operator-approved so the overwrite
// gate lets it through.
func withConfirmed(ctx context.Context) context.Context {
	return context.WithValue(ctx, confirmedKey{}, true)
}

func isConfirmed(ctx context.Context) bool {
	v, _ := ctx.Value(confirmedKey{}).(bool)
	return v
}

// issueAction records a pending overwrite and returns its console view.
func (s *Server) issueAction(sessionID int64, tool, args, kind, name, summary string) pendingAction {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	p := pendingAction{
		ID:        hex.EncodeToString(buf),
		SessionID: sessionID,
		Tool:      tool,
		Args:      args,
		Kind:      kind,
		Name:      name,
		Summary:   summary,
		Expires:   time.Now().Add(15 * time.Minute),
	}
	s.actionMu.Lock()
	if s.actions == nil {
		s.actions = map[string]*pendingAction{}
	}
	now := time.Now()
	for id, old := range s.actions {
		if now.After(old.Expires) {
			delete(s.actions, id)
		}
	}
	cp := p
	s.actions[p.ID] = &cp
	s.actionMu.Unlock()
	return p
}

// takeAction removes and returns a pending overwrite if it belongs to the
// session.
func (s *Server) takeAction(id string, sessionID int64) (*pendingAction, bool) {
	s.actionMu.Lock()
	defer s.actionMu.Unlock()
	p, ok := s.actions[id]
	if !ok {
		return nil, false
	}
	if time.Now().After(p.Expires) {
		delete(s.actions, id)
		return nil, false
	}
	if sessionID > 0 && p.SessionID != sessionID {
		return nil, false
	}
	delete(s.actions, id)
	return p, true
}

// pendingActionsFor returns unexpired actions belonging to a session without
// consuming them. Used by the console's pending-confirmation poll.
func (s *Server) pendingActionsFor(sessionID int64) []pendingAction {
	s.actionMu.Lock()
	defer s.actionMu.Unlock()
	now := time.Now()
	out := []pendingAction{}
	for _, p := range s.actions {
		if p.SessionID == sessionID && now.Before(p.Expires) {
			out = append(out, *p)
		}
	}
	return out
}

func (s *Server) pendingConfirmsFor(sessionID int64) []pendingConfirm {
	s.confirmMu.Lock()
	defer s.confirmMu.Unlock()
	now := time.Now()
	out := []pendingConfirm{}
	for _, p := range s.confirms {
		if p.SessionID == sessionID && now.Before(p.Expires) {
			out = append(out, *p)
		}
	}
	return out
}

// adminChatPending lists confirmations the console has not shown yet. It is
// polled by the AI page so background jobs cannot stall silently.
func (s *Server) adminChatPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, 405, map[string]any{"error": "GET only"})
		return
	}
	sid, _ := strconv.ParseInt(r.URL.Query().Get("session_id"), 10, 64)
	if sid <= 0 {
		s.writeJSON(w, 400, map[string]any{"error": "session_id required"})
		return
	}
	s.writeJSON(w, 200, map[string]any{
		"actions":  s.pendingActionsFor(sid),
		"confirms": s.pendingConfirmsFor(sid),
	})
}

// pendingOverwrite builds the "awaiting confirmation" tool result. It is
// reported as a successful call: the model did what it could, and the operator
// now has to approve.
func (s *Server) pendingOverwrite(sessionID int64, tool, args, kind, name, summary string, emit func(any) error) (string, bool, string) {
	p := s.issueAction(sessionID, tool, args, kind, name, summary)
	if emit != nil {
		_ = emit(map[string]any{"action": p})
	}
	b, _ := json.Marshal(map[string]any{
		"status": "awaiting_user_confirmation", "confirm_id": p.ID,
		"kind": kind, "name": name, "summary": summary,
	})
	return string(b), true, "⏸ 等待确认：" + summary
}

// pendingVerb/pendingLabel render a pending action for operator-facing notes.
// Overwrites keep their object wording; generic agent gates use the summary.
func pendingVerb(kind string) string {
	switch kind {
	case "agent_action", "plan_gate", "plan":
		return "操作"
	default:
		return "覆盖"
	}
}

func pendingLabel(p *pendingAction) string {
	switch p.Kind {
	case "agent_action", "plan_gate", "plan":
		return p.Summary
	default:
		return p.Name
	}
}

// ---------------------------------------------------------------------------
// Name lookups for the overwrite gate

func (s *Server) templateByName(name string) (store.EmailTemplate, bool) {
	list, err := s.Store.ListTemplates()
	if err != nil {
		return store.EmailTemplate{}, false
	}
	for _, t := range list {
		if t.Name == name {
			return t, true
		}
	}
	return store.EmailTemplate{}, false
}

func (s *Server) pageByName(name string) (store.LandingPage, bool) {
	list, err := s.Store.ListPages()
	if err != nil {
		return store.LandingPage{}, false
	}
	for _, p := range list {
		if p.Name == name {
			return p, true
		}
	}
	return store.LandingPage{}, false
}

func (s *Server) profileByName(name string) (store.SendingProfile, bool) {
	list, err := s.Store.ListSendingProfiles()
	if err != nil {
		return store.SendingProfile{}, false
	}
	for _, p := range list {
		if p.Name == name {
			return p, true
		}
	}
	return store.SendingProfile{}, false
}

// ---------------------------------------------------------------------------
// Inline images and self-check nudges

// maxInlineImageBytes bounds a screenshot attached to a model turn. The data
// URL is ~4/3 of this once base64-encoded.
const maxInlineImageBytes = 2 << 20

// agentVisionEnabled reports whether screenshots may be attached to model
// turns. Operators can set PHISH_AGENT_VISION=0 for text-only providers.
func agentVisionEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("PHISH_AGENT_VISION"))) {
	case "0", "false", "off", "no":
		return false
	}
	return true
}

// extractToolImage pulls the internal _image field out of a tool result so the
// base64 payload never re-enters the text context or the persisted history.
// Returns the remaining JSON and the data URL (empty when none).
func extractToolImage(raw string) (string, string) {
	if !strings.Contains(raw, `"_image"`) {
		return raw, ""
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return raw, ""
	}
	v, ok := obj["_image"]
	if !ok {
		return raw, ""
	}
	delete(obj, "_image")
	b, err := json.Marshal(obj)
	if err != nil {
		return raw, ""
	}
	var url string
	if json.Unmarshal(v, &url) != nil {
		url = ""
	}
	return string(b), url
}

// autoRepairNudge turns a failed self-check into an explicit instruction for
// the next round. Returns "" when nothing needs repair.
func autoRepairNudge(calls []llm.ToolCall, outcomes []toolOutcome) string {
	var msgs []string
	seen := map[string]bool{}
	for i, call := range calls {
		if i >= len(outcomes) || outcomes[i].ok {
			continue
		}
		var m string
		switch call.Function.Name {
		case "validate_page":
			m = "落地页自检未通过。请按 errors 逐条修复（update_landing_page），然后再次 validate_page；未通过前不要交付或发送。"
		case "create_landing_page", "update_landing_page":
			m = "落地页已保存但自检未通过。请按返回的 validation.errors 修复，并再次 validate_page。"
		case "dry_run_campaign":
			m = "干跑未通过。请按 errors 修复对应对象，再重新 dry_run_campaign。"
		case "send_campaign":
			m = "发送前检查未通过。请按返回的 errors 修复，再重新 send_campaign。"
		}
		if m != "" && !seen[m] {
			seen[m] = true
			msgs = append(msgs, m)
		}
	}
	if len(msgs) == 0 {
		return ""
	}
	return "[系统自检提示] " + strings.Join(msgs, " ") + " 修复后把结果告诉用户，不要跳过自检。"
}
