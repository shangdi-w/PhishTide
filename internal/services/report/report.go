// Package report turns per-target campaign results into a risk profile:
// one score per recipient, an aggregate per department, and a printable HTML
// report. It is deliberately offline — no database access, no network.
package report

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"phishsim/internal/core/store"
)

// Risk weights. Reporting the phish is a good behaviour and lowers the score,
// but never below zero.
const (
	scoreOpened    = 10
	scoreClicked   = 30
	scoreSubmitted = 70
	scoreReported  = -20
)

// UserRisk is one recipient's exposure in a campaign.
type UserRisk struct {
	TargetID   int64  `json:"target_id"`
	Email      string `json:"email"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	Position   string `json:"position"`
	Department string `json:"department"`
	Variant    string `json:"variant"`
	Sent       bool   `json:"sent"`
	Opened     bool   `json:"opened"`
	Clicked    bool   `json:"clicked"`
	Submitted  bool   `json:"submitted"`
	Reported   bool   `json:"reported"`
	Score      int    `json:"score"`
	Level      string `json:"level"`
}

// DepartmentRisk aggregates the recipients of one department.
type DepartmentRisk struct {
	Department string  `json:"department"`
	Users      int     `json:"users"`
	Sent       int     `json:"sent"`
	Opened     int     `json:"opened"`
	Clicked    int     `json:"clicked"`
	Submitted  int     `json:"submitted"`
	Reported   int     `json:"reported"`
	AvgScore   float64 `json:"avg_score"`
	HighRisk   int     `json:"high_risk"`
}

// VariantStat aggregates one A/B template variant.
type VariantStat struct {
	Variant    string  `json:"variant"`
	Users      int     `json:"users"`
	Sent       int     `json:"sent"`
	Opened     int     `json:"opened"`
	Clicked    int     `json:"clicked"`
	Submitted  int     `json:"submitted"`
	Reported   int     `json:"reported"`
	OpenRate   float64 `json:"open_rate"`
	ClickRate  float64 `json:"click_rate"`
	SubmitRate float64 `json:"submit_rate"`
}

// Totals holds campaign-wide counters.
type Totals struct {
	Users     int `json:"users"`
	Sent      int `json:"sent"`
	Opened    int `json:"opened"`
	Clicked   int `json:"clicked"`
	Submitted int `json:"submitted"`
	Reported  int `json:"reported"`
	HighRisk  int `json:"high_risk"`
}

// Report is the full per-campaign risk view.
type Report struct {
	CampaignID   int64            `json:"campaign_id"`
	CampaignName string           `json:"campaign_name"`
	GeneratedAt  string           `json:"generated_at"`
	Totals       Totals           `json:"totals"`
	Users        []UserRisk       `json:"users"`
	Departments  []DepartmentRisk `json:"departments"`
	Variants     []VariantStat    `json:"variants,omitempty"`
}

// Score converts one result into 0..100 and a Chinese level label.
func Score(r store.Result) int {
	n := 0
	if r.Opened {
		n += scoreOpened
	}
	if r.Clicked {
		n += scoreClicked
	}
	if r.Submitted {
		n += scoreSubmitted
	}
	if r.Reported {
		n += scoreReported
	}
	if n < 0 {
		n = 0
	}
	if n > 100 {
		n = 100
	}
	return n
}

// Level labels a score for display.
func Level(score int) string {
	switch {
	case score >= 70:
		return "高"
	case score >= 31:
		return "中"
	case score > 0:
		return "低"
	default:
		return "无"
	}
}

// Build computes the report from a campaign and its joined results.
func Build(camp store.Campaign, results []store.Result) Report {
	rep := Report{
		CampaignID:   camp.ID,
		CampaignName: camp.Name,
		GeneratedAt:  time.Now().Format("2006-01-02 15:04:05"),
		Users:        make([]UserRisk, 0, len(results)),
	}
	type acc struct {
		users, sent, opened, clicked, submitted, reported, high int
		scoreSum                                                int
	}
	depts := map[string]*acc{}
	type vacc struct{ users, sent, opened, clicked, submitted, reported int }
	variants := map[string]*vacc{}
	for _, r := range results {
		u := UserRisk{
			TargetID:   r.TargetID,
			Email:      r.Email,
			FirstName:  r.FirstName,
			LastName:   r.LastName,
			Position:   r.Position,
			Department: strings.TrimSpace(r.Department),
			Variant:    strings.TrimSpace(r.Variant),
			Sent:       r.Sent,
			Opened:     r.Opened,
			Clicked:    r.Clicked,
			Submitted:  r.Submitted,
			Reported:   r.Reported,
		}
		if u.Variant == "" {
			u.Variant = "A"
		}
		u.Score = Score(r)
		u.Level = Level(u.Score)
		rep.Users = append(rep.Users, u)

		rep.Totals.Users++
		if r.Sent {
			rep.Totals.Sent++
		}
		if r.Opened {
			rep.Totals.Opened++
		}
		if r.Clicked {
			rep.Totals.Clicked++
		}
		if r.Submitted {
			rep.Totals.Submitted++
		}
		if r.Reported {
			rep.Totals.Reported++
		}
		if u.Score >= 70 {
			rep.Totals.HighRisk++
		}

		key := u.Department
		if key == "" {
			key = "未分组"
		}
		a := depts[key]
		if a == nil {
			a = &acc{}
			depts[key] = a
		}
		a.users++
		a.scoreSum += u.Score
		if r.Sent {
			a.sent++
		}
		if r.Opened {
			a.opened++
		}
		if r.Clicked {
			a.clicked++
		}
		if r.Submitted {
			a.submitted++
		}
		if r.Reported {
			a.reported++
		}
		if u.Score >= 70 {
			a.high++
		}
		v := variants[u.Variant]
		if v == nil {
			v = &vacc{}
			variants[u.Variant] = v
		}
		v.users++
		if r.Sent {
			v.sent++
		}
		if r.Opened {
			v.opened++
		}
		if r.Clicked {
			v.clicked++
		}
		if r.Submitted {
			v.submitted++
		}
		if r.Reported {
			v.reported++
		}
	}
	sort.SliceStable(rep.Users, func(i, j int) bool {
		if rep.Users[i].Score != rep.Users[j].Score {
			return rep.Users[i].Score > rep.Users[j].Score
		}
		return rep.Users[i].Email < rep.Users[j].Email
	})
	for name, a := range depts {
		d := DepartmentRisk{
			Department: name,
			Users:      a.users,
			Sent:       a.sent,
			Opened:     a.opened,
			Clicked:    a.clicked,
			Submitted:  a.submitted,
			Reported:   a.reported,
			HighRisk:   a.high,
		}
		if a.users > 0 {
			d.AvgScore = float64(a.scoreSum) / float64(a.users)
		}
		rep.Departments = append(rep.Departments, d)
	}
	sort.SliceStable(rep.Departments, func(i, j int) bool {
		if rep.Departments[i].AvgScore != rep.Departments[j].AvgScore {
			return rep.Departments[i].AvgScore > rep.Departments[j].AvgScore
		}
		return rep.Departments[i].Department < rep.Departments[j].Department
	})
	for name, v := range variants {
		vs := VariantStat{Variant: name, Users: v.users, Sent: v.sent, Opened: v.opened,
			Clicked: v.clicked, Submitted: v.submitted, Reported: v.reported}
		if v.sent > 0 {
			vs.OpenRate = float64(v.opened) * 100 / float64(v.sent)
			vs.ClickRate = float64(v.clicked) * 100 / float64(v.sent)
			vs.SubmitRate = float64(v.submitted) * 100 / float64(v.sent)
		}
		rep.Variants = append(rep.Variants, vs)
	}
	sort.SliceStable(rep.Variants, func(i, j int) bool { return rep.Variants[i].Variant < rep.Variants[j].Variant })
	return rep
}

func pct(n, total int) string {
	if total <= 0 {
		return "0.0%"
	}
	return fmt.Sprintf("%.1f%%", float64(n)*100/float64(total))
}

func yn(b bool) string {
	if b {
		return "是"
	}
	return "—"
}

// HTML renders a self-contained, printable report. All user-controlled values
// are escaped; no external asset is required.
func (rep Report) HTML() string {
	var b strings.Builder
	esc := html.EscapeString
	fmt.Fprintf(&b, `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>钓鱼演练风险报告 · %s</title>
<style>
:root{--ink:#1f2329;--muted:#646a73;--line:#e5e6eb;--brand:#3370ff;--high:#d83931;--mid:#ff7d00;--low:#00b42a}
*{box-sizing:border-box}
body{margin:0;padding:32px;font:14px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif;color:var(--ink);background:#f7f8fa}
.wrap{max-width:1080px;margin:0 auto;background:#fff;border:1px solid var(--line);border-radius:12px;padding:32px}
h1{font-size:22px;margin:0 0 4px}
.muted{color:var(--muted);font-size:12px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0 24px}
.card{flex:1 1 120px;border:1px solid var(--line);border-radius:8px;padding:12px 14px;min-width:110px}
.card b{display:block;font-size:22px;line-height:1.2}
h2{font-size:16px;margin:26px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
table{width:100%%;border-collapse:collapse;font-size:13px}
th,td{border-bottom:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top}
th{background:#f2f3f5;font-weight:600;white-space:nowrap}
td.num,th.num{text-align:right;white-space:nowrap}
.tag{display:inline-block;padding:0 7px;border-radius:9px;font-size:12px;line-height:18px;color:#fff}
.t-high{background:var(--high)}.t-mid{background:var(--mid)}.t-low{background:var(--low)}.t-none{background:#86909c}
.toolbar{margin-top:24px;text-align:right}
button{padding:7px 16px;border:1px solid var(--brand);border-radius:6px;background:var(--brand);color:#fff;cursor:pointer}
@media print{body{padding:0;background:#fff}.wrap{border:0;border-radius:0;padding:0}.toolbar{display:none}}
</style></head><body><div class="wrap">
<h1>钓鱼演练风险报告</h1>
<div class="muted">活动 #%d · %s · 生成于 %s</div>
<div class="cards">
<div class="card"><span class="muted">目标人数</span><b>%d</b></div>
<div class="card"><span class="muted">已发送</span><b>%d</b><span class="muted">%s</span></div>
<div class="card"><span class="muted">打开</span><b>%d</b><span class="muted">%s</span></div>
<div class="card"><span class="muted">点击</span><b>%d</b><span class="muted">%s</span></div>
<div class="card"><span class="muted">提交凭证</span><b>%d</b><span class="muted">%s</span></div>
<div class="card"><span class="muted">主动报告</span><b>%d</b><span class="muted">%s</span></div>
<div class="card"><span class="muted">高风险</span><b>%d</b><span class="muted">评分 ≥70</span></div>
</div>
<h2>部门风险</h2>
<table><thead><tr><th>部门</th><th class="num">人数</th><th class="num">打开</th><th class="num">点击</th><th class="num">提交</th><th class="num">报告</th><th class="num">平均分</th><th class="num">高风险</th></tr></thead><tbody>`,
		esc(rep.CampaignName), rep.CampaignID, esc(rep.CampaignName), esc(rep.GeneratedAt),
		rep.Totals.Users, rep.Totals.Sent, pct(rep.Totals.Sent, rep.Totals.Users),
		rep.Totals.Opened, pct(rep.Totals.Opened, rep.Totals.Users),
		rep.Totals.Clicked, pct(rep.Totals.Clicked, rep.Totals.Users),
		rep.Totals.Submitted, pct(rep.Totals.Submitted, rep.Totals.Users),
		rep.Totals.Reported, pct(rep.Totals.Reported, rep.Totals.Users),
		rep.Totals.HighRisk)
	for _, d := range rep.Departments {
		fmt.Fprintf(&b, `<tr><td>%s</td><td class="num">%d</td><td class="num">%d</td><td class="num">%d</td><td class="num">%d</td><td class="num">%d</td><td class="num">%.1f</td><td class="num">%d</td></tr>`,
			esc(d.Department), d.Users, d.Opened, d.Clicked, d.Submitted, d.Reported, d.AvgScore, d.HighRisk)
	}
	b.WriteString(`</tbody></table>`)
	if len(rep.Variants) > 0 {
		b.WriteString(`<h2>A/B 模板对比</h2>
<table><thead><tr><th>分组</th><th class="num">人数</th><th class="num">已发送</th><th class="num">打开率</th><th class="num">点击率</th><th class="num">提交率</th><th class="num">举报</th></tr></thead><tbody>`)
		for _, v := range rep.Variants {
			fmt.Fprintf(&b, `<tr><td><b>%s</b></td><td class="num">%d</td><td class="num">%d</td><td class="num">%.1f%%</td><td class="num">%.1f%%</td><td class="num">%.1f%%</td><td class="num">%d</td></tr>`,
				esc(v.Variant), v.Users, v.Sent, v.OpenRate, v.ClickRate, v.SubmitRate, v.Reported)
		}
		b.WriteString(`</tbody></table>`)
	}
	b.WriteString(`<h2>个人风险明细</h2>
<table><thead><tr><th>邮箱</th><th>姓名</th><th>部门</th><th>分组</th><th>职位</th><th>发送</th><th>打开</th><th>点击</th><th>提交</th><th>报告</th><th class="num">评分</th><th>等级</th></tr></thead><tbody>`)
	for _, u := range rep.Users {
		tag := "t-none"
		switch u.Level {
		case "高":
			tag = "t-high"
		case "中":
			tag = "t-mid"
		case "低":
			tag = "t-low"
		}
		name := strings.TrimSpace(u.FirstName + " " + u.LastName)
		fmt.Fprintf(&b, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class="num"><b>%d</b></td><td><span class="tag %s">%s</span></td></tr>`,
			esc(u.Email), esc(name), esc(u.Department), esc(u.Variant), esc(u.Position),
			yn(u.Sent), yn(u.Opened), yn(u.Clicked), yn(u.Submitted), yn(u.Reported),
			u.Score, tag, esc(u.Level))
	}
	b.WriteString(`</tbody></table>
<div class="muted" style="margin-top:18px">评分口径：打开 +10，点击 +30，提交凭证 +70，主动报告 −20，范围 0–100；≥70 为高风险，31–69 为中风险，1–30 为低风险。</div>
<div class="toolbar"><button onclick="window.print()">打印 / 导出 PDF</button></div>
</div></body></html>`)
	return b.String()
}
