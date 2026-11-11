package web

// End-to-end landing page self-check. Static validation only inspects HTML;
// this check drives a real headless browser through the real capture handler:
// the page is rendered, the first form is filled and submitted, and the
// platform must record the submission before the check passes.
//
// The check needs a campaign/result pair because that is what the capture path
// keys on. A throwaway group, target, template and campaign are created and
// deleted around the run, so no operator data is touched and no statistics
// change once the check finishes.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"phishsim/internal/core/store"
	"phishsim/internal/features/clone"
)

const (
	e2eUsername = "e2e-user"
	e2ePassword = "E2E-Pass-123!"
	e2eEmail    = "e2e@example.invalid"

	e2eTimeout     = 45 * time.Second
	e2eMaxDuration = 60 * time.Second
)

// e2eCheck is the result of one end-to-end landing page check.
type e2eCheck struct {
	OK               bool     `json:"ok"`
	PageID           int64    `json:"page_id"`
	Name             string   `json:"name"`
	URL              string   `json:"url,omitempty"`
	Filled           []string `json:"filled_fields,omitempty"`
	Submitted        bool     `json:"submitted"`
	CapturedUsername string   `json:"captured_username,omitempty"`
	CapturedPassword bool     `json:"captured_password"`
	RedirectExpected string   `json:"redirect_expected,omitempty"`
	FinalURL         string   `json:"final_url,omitempty"`
	Redirected       bool     `json:"redirected"`
	DurationMS       int64    `json:"duration_ms"`
	Errors           []string `json:"errors,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
	Skipped          string   `json:"skipped,omitempty"`
}

// e2eCheckPage drives the real landing/capture handlers with headless Chrome.
func (s *Server) e2eCheckPage(page store.LandingPage) (out e2eCheck) {
	start := time.Now()
	out = e2eCheck{PageID: page.ID, Name: page.Name, RedirectExpected: page.RedirectURL}
	defer func() { out.DurationMS = time.Since(start).Milliseconds() }()

	// Do not launch a browser for a page that is already statically broken.
	static := checkLandingPage(page)
	if len(static.Errors) > 0 {
		out.Errors = append(out.Errors, static.Errors...)
		return out
	}
	// A proxy page's form is whatever the live upstream renders right now; a
	// scripted fill-and-submit could trigger real side effects upstream. Static
	// reachability is checked at creation, so the browser run is skipped.
	if page.Kind == "proxy" {
		out.Warnings = append(out.Warnings, "反向代理页面为实时转发，跳过浏览器端到端自检；用 preview_page 或直接打开预览地址确认上游渲染")
		out.OK = len(out.Errors) == 0
		return out
	}

	if !page.CaptureCredentials {
		out.Warnings = append(out.Warnings, "页面未开启凭证捕获：端到端自检只验证表单提交与跳转，不会记录凭证")
	}

	tag := randomTag()
	tplID, err := s.Store.UpsertTemplate(store.EmailTemplate{
		Name: "e2e-tpl-" + tag, Subject: "e2e self-check", HTML: "<p>e2e</p>",
	})
	if err != nil {
		out.Errors = append(out.Errors, "创建自检模板失败: "+err.Error())
		return out
	}
	gid, err := s.Store.CreateGroup("e2e-group-" + tag)
	if err != nil {
		_ = s.Store.DeleteTemplate(tplID)
		out.Errors = append(out.Errors, "创建自检群组失败: "+err.Error())
		return out
	}
	campID := int64(0)
	defer func() {
		if campID > 0 {
			_ = s.Store.DeleteCampaign(campID)
		}
		_ = s.Store.DeleteGroup(gid)
		_ = s.Store.DeleteTemplate(tplID)
	}()

	if _, err := s.Store.AddTargetsToGroup(gid, []store.Target{{Email: e2eEmail}}); err != nil {
		out.Errors = append(out.Errors, "创建自检收件人失败: "+err.Error())
		return out
	}
	campID, err = s.Store.CreateCampaign(store.Campaign{
		Name: "e2e-" + tag, EmailTemplateID: tplID, LandingPageID: page.ID,
	}, []int64{gid})
	if err != nil {
		out.Errors = append(out.Errors, "创建自检活动失败: "+err.Error())
		return out
	}
	results, err := s.Store.ListResults(campID)
	if err != nil || len(results) == 0 {
		out.Errors = append(out.Errors, "自检活动没有生成收件人结果")
		return out
	}
	res := results[0]
	camp, err := s.Store.GetCampaign(campID)
	if err != nil {
		out.Errors = append(out.Errors, "读取自检活动失败: "+err.Error())
		return out
	}

	prefix := "/l/" + res.Rid
	mux := http.NewServeMux()
	mux.HandleFunc("/l/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/l/")
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) < 1 || parts[0] != res.Rid {
			http.NotFound(w, r)
			return
		}
		if len(parts) >= 3 && parts[1] == "assets" {
			s.serveAsset(w, r, page.ID, parts[2])
			return
		}
		if len(parts) >= 2 && parts[1] == "submit" && (r.Method == http.MethodPost || r.Method == http.MethodGet) {
			s.capture(w, r, res, page, camp)
			return
		}
		body := renderLanding(page.Body, prefix)
		body = injectMobileCompat(body)
		s.serveHTML(w, body)
	})
	// The beacon script fires on load; give it a sink so the browser console
	// stays clean (it is intentionally not recorded for a self-check).
	mux.HandleFunc("/b/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	ts := httptest.NewServer(mux)
	defer ts.Close()
	out.URL = ts.URL + prefix + "/"

	sub, err := clone.SubmitForm(out.URL, e2eTimeout)
	if err != nil {
		out.Skipped = "无法运行无头浏览器（需本机安装 Chrome）"
		out.Errors = append(out.Errors, "端到端自检未运行: "+err.Error())
		return out
	}
	out.Filled = sub.Filled
	out.FinalURL = sub.FinalURL
	out.Submitted = sub.Submitted

	subs, err := s.Store.ListSubmissions(campID)
	if err != nil {
		out.Errors = append(out.Errors, "读取自检提交失败: "+err.Error())
		return out
	}
	if len(subs) == 0 {
		out.Errors = append(out.Errors, "浏览器已提交表单，但平台没有记录到 submission（检查表单 action 是否被 JS 改写或提交到了外部地址）")
		return out
	}
	got := subs[0]
	out.CapturedUsername = got.Username
	out.CapturedPassword = got.Password != ""
	if got.Username == "" {
		out.Errors = append(out.Errors, "提交已记录，但没有识别出用户名/邮箱字段")
	} else if !strings.Contains(got.Username, "e2e") {
		out.Errors = append(out.Errors, fmt.Sprintf("捕获的用户名不是自检填写值: %q", got.Username))
	}
	if page.CapturePasswords {
		if got.Password == "" {
			out.Errors = append(out.Errors, "已开启密码捕获，但提交中没有密码")
		} else if got.Password != e2ePassword {
			out.Errors = append(out.Errors, "捕获的密码不是自检填写值")
		}
	}

	// A configured "wrong password" retry keeps the browser on the retry page,
	// so a redirect is not expected in that configuration.
	if page.RedirectURL != "" && s.Cfg.FailAttempts == 0 {
		out.Redirected = strings.HasPrefix(sub.FinalURL, page.RedirectURL)
		if !out.Redirected {
			out.Errors = append(out.Errors,
				fmt.Sprintf("提交后没有跳到配置的地址（期望 %s，实际 %s）", page.RedirectURL, sub.FinalURL))
		}
	} else {
		out.Redirected = sub.Submitted
		if page.RedirectURL != "" && s.Cfg.FailAttempts > 0 {
			out.Warnings = append(out.Warnings,
				fmt.Sprintf("已配置首 %d 次登录失败重试，本次提交停在重试页属正常", s.Cfg.FailAttempts))
		}
	}
	if !sub.Submitted {
		out.Warnings = append(out.Warnings, "浏览器没有检测到页面跳转（提交可能被表单校验或脚本拦截）")
	}

	out.OK = len(out.Errors) == 0
	return out
}

// randomTag returns a short random suffix for throwaway self-check objects.
func randomTag() string {
	buf := make([]byte, 5)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}
