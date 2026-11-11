// Package geoip resolves an IPv4 address to its country and network operator
// using an offline ip2asn TSV database (iptoasn.com). Lookups are local and
// passive: the platform never sends a target's address to a third party.
//
// The expected file layout is one range per line:
//
//	1.0.0.0	1.0.0.255	13335	US	CLOUDFLARENET - Cloudflare, Inc.
//
// i.e. range_start, range_end, AS number, ISO country code, AS description.
// Both plain .tsv and gzip-compressed .gz files are accepted, so the file
// downloaded from iptoasn.com can be used as-is.
package geoip

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
)

// Info is one resolved address.
type Info struct {
	Country string `json:"country"` // Chinese display name, or the ISO code
	Code    string `json:"code"`    // ISO 3166-1 alpha-2, e.g. CN
	Org     string `json:"org"`     // AS description, e.g. CHINANET-BACKBONE
	ASN     string `json:"asn"`     // AS number as text
}

type entry struct {
	start uint32
	end   uint32
	asn   string
	code  string
	org   string
}

// DB is an in-memory, read-only IPv4 range table.
type DB struct {
	ranges []entry
}

// Load reads an ip2asn TSV file. A .gz path is decompressed transparently.
func Load(path string) (*DB, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("geoip database path required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("gunzip %s: %w", path, err)
		}
		defer zr.Close()
		r = zr
	}
	db := &DB{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, "\t", 5)
		if len(fields) < 5 {
			// Tolerate space-separated variants; the AS description keeps
			// its spaces as the remainder of the line.
			fields = strings.SplitN(line, " ", 5)
			if len(fields) < 5 {
				continue
			}
		}
		start, ok1 := parseIPv4(fields[0])
		end, ok2 := parseIPv4(fields[1])
		if !ok1 || !ok2 || end < start {
			continue
		}
		asn := strings.TrimSpace(fields[2])
		code := strings.ToUpper(strings.TrimSpace(fields[3]))
		org := strings.TrimSpace(fields[4])
		// AS 0 / country "None" means the range is not routed; labelling an
		// attacker's address as "unrouted" is worse than saying nothing.
		if asn == "0" || code == "" || code == "NONE" {
			continue
		}
		db.ranges = append(db.ranges, entry{start: start, end: end, asn: asn, code: code, org: org})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(db.ranges) == 0 {
		return nil, fmt.Errorf("no usable IPv4 ranges in %s", path)
	}
	sort.Slice(db.ranges, func(i, j int) bool { return db.ranges[i].start < db.ranges[j].start })
	return db, nil
}

// Len returns the number of loaded ranges.
func (db *DB) Len() int {
	if db == nil {
		return 0
	}
	return len(db.ranges)
}

// Lookup resolves an IPv4 address. Loopback, private, link-local and
// unspecified addresses report false, as do IPv6 addresses (the ip2asn-v4
// table has no IPv6 coverage).
func (db *DB) Lookup(ipStr string) (Info, bool) {
	if db == nil || len(db.ranges) == 0 {
		return Info{}, false
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return Info{}, false
	}
	v4 := ip.To4()
	if v4 == nil {
		return Info{}, false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return Info{}, false
	}
	n := binary.BigEndian.Uint32(v4)
	// Ranges are non-overlapping and sorted by start, so the only candidate is
	// the last range whose start is <= n.
	idx := sort.Search(len(db.ranges), func(i int) bool { return db.ranges[i].start > n })
	if idx > 0 {
		e := db.ranges[idx-1]
		if e.end >= n {
			return Info{Country: CountryName(e.code), Code: e.code, Org: e.org, ASN: e.asn}, true
		}
	}
	return Info{}, false
}

func parseIPv4(s string) (uint32, bool) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return 0, false
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(v4), true
}

// CountryName maps an ISO country code to a Chinese display name. Unknown
// codes fall through unchanged so a code is never silently lost.
func CountryName(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return ""
	}
	if name, ok := countryNames[code]; ok {
		return name
	}
	return code
}

var countryNames = map[string]string{
	"CN": "中国", "HK": "中国香港", "TW": "中国台湾", "MO": "中国澳门",
	"US": "美国", "CA": "加拿大", "MX": "墨西哥", "GT": "危地马拉", "CR": "哥斯达黎加",
	"PA": "巴拿马", "DO": "多米尼加", "CU": "古巴",
	"BR": "巴西", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚", "PE": "秘鲁",
	"VE": "委内瑞拉", "EC": "厄瓜多尔", "BO": "玻利维亚", "PY": "巴拉圭", "UY": "乌拉圭",
	"GB": "英国", "IE": "爱尔兰", "FR": "法国", "DE": "德国", "AT": "奥地利",
	"CH": "瑞士", "NL": "荷兰", "BE": "比利时", "LU": "卢森堡", "IT": "意大利",
	"ES": "西班牙", "PT": "葡萄牙", "GR": "希腊", "MT": "马耳他", "CY": "塞浦路斯",
	"DK": "丹麦", "SE": "瑞典", "NO": "挪威", "FI": "芬兰", "IS": "冰岛",
	"PL": "波兰", "CZ": "捷克", "SK": "斯洛伐克", "HU": "匈牙利", "RO": "罗马尼亚",
	"BG": "保加利亚", "SI": "斯洛文尼亚", "HR": "克罗地亚", "RS": "塞尔维亚",
	"BA": "波黑", "MK": "北马其顿", "AL": "阿尔巴尼亚", "MD": "摩尔多瓦",
	"EE": "爱沙尼亚", "LV": "拉脱维亚", "LT": "立陶宛", "BY": "白俄罗斯",
	"UA": "乌克兰", "RU": "俄罗斯", "GE": "格鲁吉亚", "AM": "亚美尼亚", "AZ": "阿塞拜疆",
	"TR": "土耳其", "IL": "以色列", "SA": "沙特阿拉伯", "AE": "阿联酋", "QA": "卡塔尔",
	"KW": "科威特", "BH": "巴林", "OM": "阿曼", "JO": "约旦", "LB": "黎巴嫩",
	"SY": "叙利亚", "IQ": "伊拉克", "IR": "伊朗", "AF": "阿富汗",
	"KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦", "KG": "吉尔吉斯斯坦", "TJ": "塔吉克斯坦",
	"TM": "土库曼斯坦", "MN": "蒙古",
	"JP": "日本", "KR": "韩国", "SG": "新加坡", "MY": "马来西亚", "TH": "泰国",
	"VN": "越南", "PH": "菲律宾", "ID": "印度尼西亚", "IN": "印度", "PK": "巴基斯坦",
	"BD": "孟加拉国", "LK": "斯里兰卡", "NP": "尼泊尔", "KH": "柬埔寨", "LA": "老挝",
	"MM": "缅甸", "BN": "文莱",
	"AU": "澳大利亚", "NZ": "新西兰", "FJ": "斐济", "PG": "巴布亚新几内亚",
	"EG": "埃及", "MA": "摩洛哥", "DZ": "阿尔及利亚", "TN": "突尼斯", "LY": "利比亚",
	"NG": "尼日利亚", "KE": "肯尼亚", "ZA": "南非", "ET": "埃塞俄比亚", "GH": "加纳",
	"TZ": "坦桑尼亚", "UG": "乌干达", "SN": "塞内加尔", "CI": "科特迪瓦",
	"CM": "喀麦隆", "ZW": "津巴布韦", "MZ": "莫桑比克", "AO": "安哥拉",
}
