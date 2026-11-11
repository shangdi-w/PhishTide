package web

import "phishsim/internal/core/store"

// Offline GeoIP helpers. The database is loaded once at boot from a local
// ip2asn TSV file; lookups never leave the process.

// geoLookup adapts the loaded database to analyze.GeoLookup.
func (s *Server) geoLookup(ip string) (country, org string, ok bool) {
	if s.Geo == nil {
		return "", "", false
	}
	info, found := s.Geo.Lookup(ip)
	if !found {
		return "", "", false
	}
	return info.Country, info.Org, true
}

// geoLabels reports the display country and operator for one IP, or two empty
// strings when no database is loaded or the address does not resolve.
func (s *Server) geoLabels(ip string) (string, string) {
	country, org, ok := s.geoLookup(ip)
	if !ok {
		return "", ""
	}
	return country, org
}

// enrichSubmissions fills the read-time Country/Org fields. It is a no-op when
// no database is loaded, so callers never need a nil check.
func (s *Server) enrichSubmissions(subs []store.Submission) {
	if s.Geo == nil {
		return
	}
	for i := range subs {
		if country, org, ok := s.geoLookup(subs[i].IP); ok {
			subs[i].Country, subs[i].Org = country, org
		}
	}
}
