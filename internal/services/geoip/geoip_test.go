package geoip

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

const fixtureTSV = `# range_start	range_end	AS	country	org
1.0.0.0	1.0.0.255	13335	US	CLOUDFLARENET - Cloudflare, Inc.
1.0.1.0	1.0.3.255	0	None	Not routed
1.0.4.0	1.0.7.255	38803	AU	GTELECOM-AS-AP - Gtelecom Pty Ltd
114.114.0.0	114.114.255.255	4134	CN	CHINANET-BACKBONE
`

func writeFixture(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAndLookup(t *testing.T) {
	db, err := Load(writeFixture(t, "ip2asn-v4.tsv", fixtureTSV))
	if err != nil {
		t.Fatal(err)
	}
	if db.Len() != 3 {
		t.Fatalf("ranges = %d, want 3 (unrouted rows skipped)", db.Len())
	}
	cases := []struct {
		ip      string
		country string
		code    string
		org     string
	}{
		{"1.0.0.5", "美国", "US", "CLOUDFLARENET - Cloudflare, Inc."},
		{"114.114.114.114", "中国", "CN", "CHINANET-BACKBONE"},
	}
	for _, c := range cases {
		info, ok := db.Lookup(c.ip)
		if !ok || info.Country != c.country || info.Code != c.code || info.Org != c.org {
			t.Fatalf("lookup %s = %+v ok=%v", c.ip, info, ok)
		}
	}
	// Range boundaries are inclusive on both ends.
	if _, ok := db.Lookup("1.0.0.0"); !ok {
		t.Fatal("first address of a range should resolve")
	}
	if _, ok := db.Lookup("1.0.0.255"); !ok {
		t.Fatal("last address of a range should resolve")
	}
	if _, ok := db.Lookup("1.0.1.0"); ok {
		t.Fatal("unrouted range should not resolve")
	}
	if _, ok := db.Lookup("9.9.9.9"); ok {
		t.Fatal("address outside the table should not resolve")
	}
}

func TestLookupSkipsNonPublic(t *testing.T) {
	db, err := Load(writeFixture(t, "ip2asn-v4.tsv", fixtureTSV))
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.9", "169.254.1.1", "0.0.0.0", "::1", "2001:db8::1", "not-an-ip", ""} {
		if info, ok := db.Lookup(ip); ok {
			t.Fatalf("%q unexpectedly resolved to %+v", ip, info)
		}
	}
}

func TestLoadGzip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip2asn-v4.tsv.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err := zw.Write([]byte(fixtureTSV)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if info, ok := db.Lookup("114.114.114.114"); !ok || info.Code != "CN" {
		t.Fatalf("gz lookup = %+v ok=%v", info, ok)
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(""); err == nil {
		t.Fatal("empty path should fail")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.tsv")); err == nil {
		t.Fatal("missing file should fail")
	}
	if _, err := Load(writeFixture(t, "empty.tsv", "# only a comment\n")); err == nil {
		t.Fatal("file without ranges should fail")
	}
}

func TestCountryName(t *testing.T) {
	if got := CountryName("cn"); got != "中国" {
		t.Fatalf("cn = %q", got)
	}
	if got := CountryName("ZZ"); got != "ZZ" {
		t.Fatalf("unknown code = %q", got)
	}
	if got := CountryName(""); got != "" {
		t.Fatalf("empty = %q", got)
	}
}
