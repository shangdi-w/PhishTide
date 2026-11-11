package web

import (
	"net"
	"net/http"
	"strings"
	"time"

	"phishsim/internal/core/store"
)

// Link access policy: an optional per-campaign lifetime, a burn-after-submit
// switch, and IP allow/deny lists. All are enforced on the public landing
// route before a page or asset is served.

const expiredPage = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>链接已失效</title></head>
<body style="font-family:-apple-system,'Segoe UI','Microsoft YaHei',sans-serif;background:#f7f8fa;color:#1f2329;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
<div style="max-width:420px;padding:32px;text-align:center"><h1 style="font-size:20px">链接已失效</h1><p style="color:#646a73;font-size:14px">该链接已过期或已被使用，请联系发件人获取新的链接。</p></div>
</body></html>`

const blockedPage = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>无法访问</title></head>
<body style="font-family:-apple-system,'Segoe UI','Microsoft YaHei',sans-serif;background:#f7f8fa;color:#1f2329;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
<div style="max-width:420px;padding:32px;text-align:center"><h1 style="font-size:20px">无法访问</h1><p style="color:#646a73;font-size:14px">当前网络环境不允许访问该链接。</p></div>
</body></html>`

// linkExpired reports whether the campaign's link policy rejects this result.
func linkExpired(camp store.Campaign, res store.Result) bool {
	if camp.LinkOnce && res.Submitted {
		return true
	}
	if camp.LinkTTLHours <= 0 || res.SentAt == "" {
		return false
	}
	sent, err := time.Parse(time.RFC3339Nano, res.SentAt)
	if err != nil {
		return false
	}
	return time.Now().After(sent.Add(time.Duration(camp.LinkTTLHours) * time.Hour))
}

// linkIPBlocked applies the campaign's allow/deny lists to a client IP.
func linkIPBlocked(camp store.Campaign, ip string) bool {
	if ip == "" {
		return false
	}
	if matchIPList(camp.IPDeny, ip) {
		return true
	}
	if entries := parseIPList(camp.IPAllow); len(entries) > 0 {
		return !matchIPList(camp.IPAllow, ip)
	}
	return false
}

// ipRule is one parsed allow/deny entry.
type ipRule struct {
	ip  net.IP
	net *net.IPNet
}

func splitIPList(list string) []string {
	return strings.FieldsFunc(list, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
}

// invalidIPList returns entries that parse as neither an IP nor a CIDR, so a
// typo in an allow/deny list is rejected instead of silently ignored.
func invalidIPList(list string) []string {
	var bad []string
	for _, f := range splitIPList(list) {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(f); err == nil {
			continue
		}
		if net.ParseIP(f) == nil {
			bad = append(bad, f)
		}
	}
	return bad
}

func parseIPList(list string) []ipRule {
	fields := splitIPList(list)
	out := make([]ipRule, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(f); err == nil {
			out = append(out, ipRule{net: n})
			continue
		}
		if ip := net.ParseIP(f); ip != nil {
			out = append(out, ipRule{ip: ip})
		}
	}
	return out
}

func matchIPList(list, ip string) bool {
	addr := net.ParseIP(strings.TrimSpace(ip))
	if addr == nil {
		return false
	}
	for _, r := range parseIPList(list) {
		switch {
		case r.net != nil && r.net.Contains(addr):
			return true
		case r.ip != nil && r.ip.Equal(addr):
			return true
		}
	}
	return false
}

// serveHTMLStatus writes an operator-owned HTML error page with a status code.
func (s *Server) serveHTMLStatus(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}
