// Package analyze computes a platform-wide data snapshot (campaign stats, IP
// summary, submissions, behavior) so the operator — and the AI assistant —
// can answer questions like "这次演练效果如何" or "哪些 IP 提交了".
package analyze

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"phishsim/internal/core/store"
)

// CampaignStat is one campaign's aggregate metrics.
type CampaignStat struct {
	ID         int64   `json:"id"`
	Name       string  `json:"name"`
	Targets    int     `json:"targets"`
	Sent       int     `json:"sent"`
	Opened     int     `json:"opened"`
	Clicked    int     `json:"clicked"`
	Submitted  int     `json:"submitted"`
	Reported   int     `json:"reported"`
	OpenRate   float64 `json:"open_rate"`
	ClickRate  float64 `json:"click_rate"`
	SubmitRate float64 `json:"submit_rate"`
}

// IPCount is one IP with its activity counts.
type IPCount struct {
	IP          string `json:"ip"`
	Class       string `json:"class"` // "内网" | "公网" | "环回" | "其他"
	Country     string `json:"country,omitempty"`
	Org         string `json:"org,omitempty"`
	Events      int    `json:"events"`
	Submissions int    `json:"submissions"`
}

// GeoLookup resolves a public IP to a display country and network operator.
// It is optional: nil means no offline GeoIP database is configured.
type GeoLookup func(ip string) (country, org string, ok bool)

// BehaviorSummary aggregates client-side behavior events.
type BehaviorSummary struct {
	PageLoads      int     `json:"page_loads"`
	DwellEvents    int     `json:"dwell_events"`
	Clicks         int     `json:"clicks"`
	FieldFocus     int     `json:"field_focus"`
	SubmitAttempts int     `json:"submit_attempts"`
	AvgDwellSec    float64 `json:"avg_dwell_sec"`
	MaxDwellSec    float64 `json:"max_dwell_sec"`
}

// GroupStat is one target group's size and department-ish keywords.
type GroupStat struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Target int    `json:"target"`
}

// Funnel is the stage-by-stage conversion across the whole platform.
type Funnel struct {
	Sent       int     `json:"sent"`
	Opened     int     `json:"opened"`
	Clicked    int     `json:"clicked"`
	Submitted  int     `json:"submitted"`
	Reported   int     `json:"reported"`
	OpenRate   float64 `json:"open_rate"`
	ClickRate  float64 `json:"click_rate"`
	SubmitRate float64 `json:"submit_rate"`
	ReportRate float64 `json:"report_rate"`
}

// Path is one target's ordered behavior-event sequence.
type Path struct {
	Email string   `json:"email"`
	Steps []string `json:"steps"`
}

// Snapshot is the full platform analysis.
type Snapshot struct {
	Campaigns   []CampaignStat     `json:"campaigns"`
	Groups      []GroupStat        `json:"groups"`
	IPs         []IPCount          `json:"ips"`
	Submissions []store.Submission `json:"submissions"`
	Behavior    BehaviorSummary    `json:"behavior"`
	Funnel      Funnel             `json:"funnel"`
	Paths       []Path             `json:"paths"`
}

// Build aggregates all platform data into one snapshot. geo enriches public
// source IPs with country and operator; pass nil when no database is loaded.
func Build(s *store.Store, geo GeoLookup) (*Snapshot, error) {
	snap := &Snapshot{
		Campaigns:   []CampaignStat{},
		Groups:      []GroupStat{},
		IPs:         []IPCount{},
		Submissions: []store.Submission{},
		Paths:       []Path{},
	}
	campaigns, err := s.ListCampaigns()
	if err != nil {
		return nil, err
	}
	groups, _ := s.ListGroups()

	type ipAgg struct {
		events, submissions int
	}
	ipMap := map[string]*ipAgg{}
	ipClass := map[string]string{}
	beh := BehaviorSummary{}
	funnel := Funnel{}
	pathSteps := map[int64][]string{}
	pathEmail := map[int64]string{}

	for _, g := range groups {
		snap.Groups = append(snap.Groups, GroupStat{ID: g.ID, Name: g.Name, Target: g.TargetCount})
	}

	for _, c := range campaigns {
		cs := CampaignStat{ID: c.ID, Name: c.Name, Targets: c.Targets, Sent: c.Sent,
			Opened: c.Opened, Clicked: c.Clicked, Submitted: c.Submitted, Reported: c.Reported}
		cs.OpenRate = rate(c.Opened, c.Sent)
		cs.ClickRate = rate(c.Clicked, c.Opened)
		cs.SubmitRate = rate(c.Submitted, c.Clicked)
		snap.Campaigns = append(snap.Campaigns, cs)

		funnel.Sent += c.Sent
		funnel.Opened += c.Opened
		funnel.Clicked += c.Clicked
		funnel.Submitted += c.Submitted
		funnel.Reported += c.Reported

		subs, _ := s.ListSubmissions(c.ID)
		snap.Submissions = append(snap.Submissions, subs...)
		for _, sub := range subs {
			agg := ipMap[sub.IP]
			if agg == nil {
				agg = &ipAgg{}
				ipMap[sub.IP] = agg
				ipClass[sub.IP] = ClassifyIP(sub.IP)
			}
			agg.submissions++
		}

		// Map target id -> email for behavior paths.
		if results, err := s.ListResults(c.ID); err == nil {
			for _, r := range results {
				pathEmail[r.TargetID] = r.Email
			}
		}

		events, _ := s.ListEvents(c.ID)
		// ListEvents is DESC; reverse to chronological order for paths.
		for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
			events[i], events[j] = events[j], events[i]
		}
		var dwellSum, dwellMax float64
		dwellN := 0
		for _, e := range events {
			agg := ipMap[e.IP]
			if agg == nil {
				agg = &ipAgg{}
				ipMap[e.IP] = agg
				ipClass[e.IP] = ClassifyIP(e.IP)
			}
			agg.events++
			switch e.Kind {
			case "page_load":
				beh.PageLoads++
				pathSteps[e.TargetID] = append(pathSteps[e.TargetID], "加载")
			case "dwell":
				beh.DwellEvents++
				var secs float64
				fmt.Sscanf(e.Detail, "%f", &secs)
				if secs > 0 {
					dwellSum += secs
					dwellN++
					if secs > dwellMax {
						dwellMax = secs
					}
				}
			case "page_click":
				beh.Clicks++
				pathSteps[e.TargetID] = append(pathSteps[e.TargetID], "点击元素")
			case "field_focus":
				beh.FieldFocus++
				pathSteps[e.TargetID] = append(pathSteps[e.TargetID], "聚焦")
			case "submit_attempt":
				beh.SubmitAttempts++
				pathSteps[e.TargetID] = append(pathSteps[e.TargetID], "提交尝试")
			case "opened":
				pathSteps[e.TargetID] = append(pathSteps[e.TargetID], "打开")
			case "clicked":
				pathSteps[e.TargetID] = append(pathSteps[e.TargetID], "点击")
			case "submitted":
				pathSteps[e.TargetID] = append(pathSteps[e.TargetID], "提交")
			case "reported":
				pathSteps[e.TargetID] = append(pathSteps[e.TargetID], "举报")
			}
		}
		if dwellN > 0 {
			beh.AvgDwellSec = dwellSum / float64(dwellN)
		}
		if dwellMax > beh.MaxDwellSec {
			beh.MaxDwellSec = dwellMax
		}
	}

	funnel.OpenRate = rate(funnel.Opened, funnel.Sent)
	funnel.ClickRate = rate(funnel.Clicked, funnel.Opened)
	funnel.SubmitRate = rate(funnel.Submitted, funnel.Clicked)
	funnel.ReportRate = rate(funnel.Reported, funnel.Submitted)
	snap.Funnel = funnel

	for ip, agg := range ipMap {
		c := IPCount{IP: ip, Class: ipClass[ip], Events: agg.events, Submissions: agg.submissions}
		if geo != nil {
			if country, org, ok := geo(ip); ok {
				c.Country, c.Org = country, org
			}
		}
		snap.IPs = append(snap.IPs, c)
	}
	sort.Slice(snap.IPs, func(i, j int) bool {
		if snap.IPs[i].Submissions != snap.IPs[j].Submissions {
			return snap.IPs[i].Submissions > snap.IPs[j].Submissions
		}
		return snap.IPs[i].Events > snap.IPs[j].Events
	})

	// Behavior paths: targets with at least 2 steps, sorted, capped.
	ids := make([]int64, 0, len(pathSteps))
	for id, steps := range pathSteps {
		if len(steps) >= 2 {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		if len(snap.Paths) >= 100 {
			break
		}
		snap.Paths = append(snap.Paths, Path{Email: pathEmail[id], Steps: pathSteps[id]})
	}

	snap.Behavior = beh
	return snap, nil
}

// regionSummary counts resolved countries across source IPs, most active
// first, so the text summary can answer "大家都是从哪儿点开的".
func regionSummary(ips []IPCount) string {
	counts := map[string]int{}
	order := []string{}
	for _, ip := range ips {
		if ip.Country == "" {
			continue
		}
		if counts[ip.Country] == 0 {
			order = append(order, ip.Country)
		}
		counts[ip.Country]++
	}
	if len(order) == 0 {
		return ""
	}
	sort.SliceStable(order, func(i, j int) bool { return counts[order[i]] > counts[order[j]] })
	var b strings.Builder
	b.WriteString("来源地区：")
	for i, name := range order {
		if i >= 6 {
			b.WriteString("…")
			break
		}
		if i > 0 {
			b.WriteString("、")
		}
		b.WriteString(fmt.Sprintf("%s(%d)", name, counts[name]))
	}
	b.WriteString("\n")
	return b.String()
}

func rate(num, den int) float64 {
	if den <= 0 {
		return 0
	}
	return float64(num) / float64(den)
}

// cache holds the last computed snapshot so repeated reads within ttl don't
// rescan the database.
var cache struct {
	mu   sync.Mutex
	at   time.Time
	snap *Snapshot
	geo  GeoLookup
}

// BuildCached returns the snapshot, recomputing at most once per ttl.
func BuildCached(s *store.Store, ttl time.Duration, geo GeoLookup) (*Snapshot, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	// A snapshot built without geo enrichment must not be served once a
	// database is loaded (or vice versa), so presence is part of the key.
	if cache.snap != nil && time.Since(cache.at) < ttl && (cache.geo == nil) == (geo == nil) {
		return cache.snap, nil
	}
	snap, err := Build(s, geo)
	if err != nil {
		return nil, err
	}
	cache.snap, cache.geo = snap, geo
	cache.at = time.Now()
	return snap, nil
}

// ClassifyIP labels an IP as 内网/环回/公网/其他.
func ClassifyIP(ipStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "其他"
	}
	switch {
	case ip.IsLoopback():
		return "环回"
	case ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified():
		return "内网"
	default:
		return "公网"
	}
}

// Text renders a compact human-readable summary, used both in the admin UI and
// as grounding context for the AI assistant.
func (s *Snapshot) Text() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("共 %d 个活动、%d 个群组、%d 条提交。\n", len(s.Campaigns), len(s.Groups), len(s.Submissions)))
	for _, c := range s.Campaigns {
		b.WriteString(fmt.Sprintf("- 活动「%s」：目标 %d，已发 %d，打开率 %.0f%%，点击率 %.0f%%，提交率 %.0f%%，举报 %d\n",
			c.Name, c.Targets, c.Sent, c.OpenRate*100, c.ClickRate*100, c.SubmitRate*100, c.Reported))
	}
	if len(s.Groups) > 0 {
		b.WriteString("群组：")
		for i, g := range s.Groups {
			if i > 0 {
				b.WriteString("、")
			}
			b.WriteString(fmt.Sprintf("%s(%d)", g.Name, g.Target))
		}
		b.WriteString("\n")
	}
	if len(s.IPs) > 0 {
		b.WriteString("来源 IP：")
		for i, ip := range s.IPs {
			if i >= 8 {
				b.WriteString("…")
				break
			}
			if i > 0 {
				b.WriteString("、")
			}
			label := ip.Class
			if ip.Country != "" {
				label += "/" + ip.Country
			}
			b.WriteString(fmt.Sprintf("%s(%s,提交%d)", ip.IP, label, ip.Submissions))
		}
		b.WriteString("\n")
		b.WriteString(regionSummary(s.IPs))
	}
	if s.Behavior.DwellEvents > 0 || s.Behavior.SubmitAttempts > 0 {
		b.WriteString(fmt.Sprintf("行为：平均停留 %.0fs，字段聚焦 %d，提交尝试 %d，点击 %d\n",
			s.Behavior.AvgDwellSec, s.Behavior.FieldFocus, s.Behavior.SubmitAttempts, s.Behavior.Clicks))
	}
	if s.Funnel.Sent > 0 {
		b.WriteString(fmt.Sprintf("漏斗：发送 %d → 打开 %d(%.0f%%) → 点击 %d(%.0f%%) → 提交 %d(%.0f%%) → 举报 %d\n",
			s.Funnel.Sent, s.Funnel.Opened, s.Funnel.OpenRate*100,
			s.Funnel.Clicked, s.Funnel.ClickRate*100,
			s.Funnel.Submitted, s.Funnel.SubmitRate*100, s.Funnel.Reported))
	}
	return strings.TrimSpace(b.String())
}
