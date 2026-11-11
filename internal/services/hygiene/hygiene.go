// Package hygiene audits a recipient list before a campaign is sent: malformed
// addresses, duplicate rows, role/admin mailboxes, disposable domains, and
// domains with no usable MX record. It only reads DNS; nothing is sent.
package hygiene

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"phishsim/internal/core/store"
)

// Issue kinds reported by Audit.
const (
	KindInvalid    = "invalid"    // address fails syntax checks
	KindDuplicate  = "duplicate"  // repeated address (case-insensitive)
	KindRole       = "role"       // shared mailbox such as info@ / admin@
	KindDisposable = "disposable" // throwaway mail provider
	KindNoMX       = "no-mx"      // domain has no MX record and no A fallback
	KindMXError    = "mx-error"   // DNS lookup failed (transient or blocked)
)

// Issue is one problem found in the list.
type Issue struct {
	Email  string `json:"email"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// DomainStatus records the MX check for one domain.
type DomainStatus struct {
	Domain string   `json:"domain"`
	MX     []string `json:"mx"`
	Error  string   `json:"error,omitempty"`
}

// Report is the audit result.
type Report struct {
	Total   int            `json:"total"`
	Unique  int            `json:"unique"`
	Issues  []Issue        `json:"issues"`
	Counts  map[string]int `json:"counts"`
	Domains []DomainStatus `json:"domains,omitempty"`
}

// roleMailboxes are shared/administrative local parts that usually belong to
// a team rather than a person. Sending a drill to them rarely measures an
// individual and can reach a ticket queue.
var roleMailboxes = map[string]bool{
	"info": true, "admin": true, "administrator": true, "support": true,
	"sales": true, "hr": true, "security": true, "postmaster": true,
	"webmaster": true, "hostmaster": true, "abuse": true, "noc": true,
	"it": true, "helpdesk": true, "help": true, "office": true,
	"billing": true, "accounts": true, "contact": true, "jobs": true,
	"marketing": true, "noreply": true, "no-reply": true, "donotreply": true,
	"do-not-reply": true, "mailer-daemon": true, "root": true, "test": true,
	"service": true, "team": true, "all": true, "everyone": true,
}

// disposableDomains is a pragmatic blocklist of throwaway mail providers.
var disposableDomains = map[string]bool{
	"mailinator.com": true, "guerrillamail.com": true, "guerrillamail.net": true,
	"guerrillamail.org": true, "guerrillamailblock.com": true,
	"10minutemail.com": true, "10minutemail.net": true, "tempmail.com": true,
	"temp-mail.org": true, "tempmail.net": true, "yopmail.com": true,
	"yopmail.fr": true, "sharklasers.com": true, "trashmail.com": true,
	"maildrop.cc": true, "getnada.com": true, "nada.email": true,
	"dispostable.com": true, "throwawaymail.com": true, "fakeinbox.com": true,
	"mailnesia.com": true, "spamgourmet.com": true, "mintemail.com": true,
	"mohmal.com": true, "mailcatch.com": true, "mytemp.email": true,
	"tempinbox.com": true, "emailondeck.com": true, "burnermail.io": true,
	"mail.tm": true, "inboxkitten.com": true, "moakt.com": true,
}

// Audit inspects the list. checkMX performs DNS lookups for each unique
// domain; timeout bounds the whole MX pass (default 8 seconds).
func Audit(targets []store.Target, checkMX bool, timeout time.Duration) Report {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	rep := Report{Total: len(targets), Counts: map[string]int{}}
	seen := map[string]bool{}
	for _, t := range targets {
		email := strings.TrimSpace(t.Email)
		if email == "" {
			rep.addIssue("", KindInvalid, "空地址")
			continue
		}
		if !validEmail(email) {
			rep.addIssue(email, KindInvalid, "格式不合法")
			continue
		}
		lower := strings.ToLower(email)
		if seen[lower] {
			rep.addIssue(email, KindDuplicate, "名单内重复")
			continue
		}
		seen[lower] = true
		rep.Unique++
		local, domain, _ := strings.Cut(lower, "@")
		if roleMailboxes[local] {
			rep.addIssue(email, KindRole, "共享/职能邮箱")
		}
		if disposableDomains[domain] {
			rep.addIssue(email, KindDisposable, "一次性邮箱域名")
		}
	}
	if checkMX {
		rep.Domains = checkDomains(targets, timeout)
		for _, d := range rep.Domains {
			switch {
			case d.Error != "":
				rep.addIssue("@"+d.Domain, KindMXError, d.Error)
			case len(d.MX) == 0:
				rep.addIssue("@"+d.Domain, KindNoMX, "无 MX 记录（会退信或落到 A 记录）")
			}
		}
	}
	return rep
}

func (r *Report) addIssue(email, kind, detail string) {
	r.Issues = append(r.Issues, Issue{Email: email, Kind: kind, Detail: detail})
	r.Counts[kind]++
}

// checkDomains looks up MX records for each unique domain, with a shared
// deadline and a small cache so a repeated domain costs one lookup.
func checkDomains(targets []store.Target, timeout time.Duration) []DomainStatus {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resolver := net.DefaultResolver
	cache := map[string]DomainStatus{}
	for _, t := range targets {
		_, domain, ok := strings.Cut(strings.ToLower(strings.TrimSpace(t.Email)), "@")
		if !ok || domain == "" {
			continue
		}
		if _, done := cache[domain]; done {
			continue
		}
		ds := DomainStatus{Domain: domain}
		mxs, err := resolver.LookupMX(ctx, domain)
		if err != nil {
			if ctx.Err() != nil {
				ds.Error = "DNS 查询超时"
			} else {
				ds.Error = err.Error()
			}
		} else {
			for _, mx := range mxs {
				host := strings.TrimSuffix(strings.TrimSpace(mx.Host), ".")
				if host != "" {
					ds.MX = append(ds.MX, fmt.Sprintf("%s (prio %d)", host, mx.Pref))
				}
			}
			sort.Strings(ds.MX)
		}
		cache[domain] = ds
	}
	out := make([]DomainStatus, 0, len(cache))
	for _, ds := range cache {
		out = append(out, ds)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// validEmail mirrors the storage-boundary check: one @, no whitespace or
// header separators, a dot in the domain, and bounded length.
func validEmail(s string) bool {
	if len(s) > 254 {
		return false
	}
	if strings.ContainsAny(s, " \t\r\n<>,;\"'") {
		return false
	}
	if strings.Count(s, "@") != 1 {
		return false
	}
	at := strings.IndexByte(s, '@')
	if at <= 0 || at >= len(s)-1 {
		return false
	}
	domain := s[at+1:]
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	for _, c := range domain {
		if !(c == '.' || c == '-' || c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}
