package web

// Optional outbound guard: when PHISH_FETCH_ALLOWLIST is set (comma-separated
// domains, subdomains included), the agent may only fetch/proxy those hosts.

import (
	"net"
	"os"
	"strings"
)

func (s *Server) fetchAllowed(host string) bool {
	raw := strings.TrimSpace(os.Getenv("PHISH_FETCH_ALLOWLIST"))
	if raw == "" {
		return true
	}
	h := strings.ToLower(strings.TrimSpace(host))
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = strings.TrimSuffix(h, ".")
	for _, item := range strings.Split(raw, ",") {
		d := strings.ToLower(strings.TrimSpace(item))
		if d == "" {
			continue
		}
		d = strings.TrimPrefix(strings.TrimPrefix(d, "*."), ".")
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}
