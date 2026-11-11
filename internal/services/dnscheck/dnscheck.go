// Package dnscheck validates a sending domain's SPF, DKIM, and DMARC DNS
// records, so the operator can see what is missing for deliverability.
package dnscheck

import (
	"net"
	"strings"
)

// Record is one SPF/DKIM/DMARC DNS record lookup.
type Record struct {
	Kind   string `json:"kind"` // "spf" | "dkim" | "dmarc"
	Domain string `json:"domain"`
	Value  string `json:"value"`
	Found  bool   `json:"found"`
}

// Result is the full deliverability check for one domain.
type Result struct {
	Domain  string   `json:"domain"`
	SPFOK   bool     `json:"spf_ok"`
	DKIMOK  bool     `json:"dkim_ok"`
	DMARCOK bool     `json:"dmarc_ok"`
	Records []Record `json:"records"`
}

// Check looks up the SPF, DKIM, and DMARC records for a domain.
func Check(domain string) Result {
	domain = strings.TrimSpace(domain)
	if i := strings.LastIndexByte(domain, '@'); i >= 0 {
		domain = domain[i+1:]
	}
	r := Result{Domain: domain, Records: []Record{}}

	// SPF: TXT at the domain apex starting with "v=spf1".
	if txts, err := net.LookupTXT(domain); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
				r.Records = append(r.Records, Record{Kind: "spf", Domain: domain, Value: t, Found: true})
				r.SPFOK = true
			}
		}
	}
	if !r.SPFOK {
		r.Records = append(r.Records, Record{Kind: "spf", Domain: domain, Found: false})
	}

	// DKIM: TXT at <selector>._domainkey.<domain>. Try common selectors.
	for _, sel := range []string{"default", "google", "selector1", "selector2", "dkim", "mail", "s1", "k1"} {
		name := sel + "._domainkey." + domain
		if txts, err := net.LookupTXT(name); err == nil && len(txts) > 0 {
			r.Records = append(r.Records, Record{Kind: "dkim", Domain: name, Value: strings.Join(txts, " "), Found: true})
			r.DKIMOK = true
			break
		}
	}
	if !r.DKIMOK {
		r.Records = append(r.Records, Record{Kind: "dkim", Domain: "<selector>._domainkey." + domain, Found: false})
	}

	// DMARC: TXT at _dmarc.<domain> starting with "v=dmarc1".
	if txts, err := net.LookupTXT("_dmarc." + domain); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
				r.Records = append(r.Records, Record{Kind: "dmarc", Domain: "_dmarc." + domain, Value: t, Found: true})
				r.DMARCOK = true
			}
		}
	}
	if !r.DMARCOK {
		r.Records = append(r.Records, Record{Kind: "dmarc", Domain: "_dmarc." + domain, Found: false})
	}
	return r
}
