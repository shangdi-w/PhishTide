package analyze

import (
	"strings"
	"testing"
)

func TestClassifyIP(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1":   "环回",
		"10.1.2.3":    "内网",
		"192.168.0.9": "内网",
		"8.8.8.8":     "公网",
		"":            "其他",
		"nope":        "其他",
	}
	for ip, want := range cases {
		if got := ClassifyIP(ip); got != want {
			t.Fatalf("ClassifyIP(%q) = %q, want %q", ip, got, want)
		}
	}
}

func TestRegionSummary(t *testing.T) {
	ips := []IPCount{
		{IP: "1.1.1.1", Country: "美国"},
		{IP: "2.2.2.2", Country: "中国"},
		{IP: "3.3.3.3", Country: "中国"},
		{IP: "10.0.0.1"}, // unresolved: private addresses carry no country
		{IP: "4.4.4.4", Country: "日本"},
	}
	got := regionSummary(ips)
	if !strings.Contains(got, "中国(2)") || !strings.Contains(got, "美国(1)") {
		t.Fatalf("summary = %q", got)
	}
	if strings.Index(got, "中国(2)") > strings.Index(got, "美国(1)") {
		t.Fatalf("summary should lead with the largest country: %q", got)
	}
	if regionSummary([]IPCount{{IP: "10.0.0.1"}}) != "" {
		t.Fatal("no resolved IPs should render no summary")
	}
}

func TestTextIncludesGeo(t *testing.T) {
	snap := Snapshot{
		IPs: []IPCount{
			{IP: "1.0.0.5", Class: "公网", Country: "美国", Org: "CLOUDFLARENET", Submissions: 2},
			{IP: "114.114.114.114", Class: "公网", Country: "中国", Org: "CHINANET", Submissions: 1},
		},
	}
	txt := snap.Text()
	if !strings.Contains(txt, "1.0.0.5(公网/美国,提交2)") {
		t.Fatalf("per-IP geo missing: %q", txt)
	}
	if !strings.Contains(txt, "来源地区：") || !strings.Contains(txt, "美国(1)") {
		t.Fatalf("region summary missing: %q", txt)
	}
}
