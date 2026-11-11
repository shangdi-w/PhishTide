// Package pdftext extracts readable text from simple PDF files without
// external tools. It supports uncompressed and FlateDecode content streams and
// the common Tj/TJ operators; scanned PDFs and CID-encoded fonts yield little
// or no text, which callers must treat as "not extracted".
package pdftext

import (
	"bytes"
	"compress/zlib"
	"io"
	"regexp"
	"strings"
	"unicode/utf16"
)

var (
	tjRe    = regexp.MustCompile(`\(((?:\\.|[^\\()])*)\)\s*Tj`)
	tjArrRe = regexp.MustCompile(`\[((?:\\.|[^\]])*)\]\s*TJ`)
	strRe   = regexp.MustCompile(`\(((?:\\.|[^\\()])*)\)`)
)

const (
	maxStreamBytes    = 10 << 20
	totalDecodeBudget = 32 << 20
	maxStreams        = 64
)

// Extract returns whitespace-normalised text, capped at maxChars runes.
func Extract(data []byte, maxChars int) string {
	if maxChars <= 0 {
		maxChars = 20000
	}
	lower := bytes.ToLower(data)
	if bytes.Contains(lower, []byte("/encrypt")) {
		return ""
	}
	var b strings.Builder
	offset := 0
	streams := 0
	budget := totalDecodeBudget
	for {
		i := bytes.Index(lower[offset:], []byte("stream"))
		if i < 0 {
			break
		}
		if streams >= maxStreams || budget <= 0 {
			break
		}
		streams++
		start := offset + i + len("stream")
		for start < len(data) && (data[start] == '\r' || data[start] == '\n') {
			start++
		}
		endRel := bytes.Index(lower[start:], []byte("endstream"))
		if endRel < 0 {
			break
		}
		end := start + endRel
		raw := data[start:end]
		dictStart := start - 500
		if dictStart < 0 {
			dictStart = 0
		}
		if bytes.Contains(lower[dictStart:start], []byte("/flatedecode")) {
			limit := maxStreamBytes
			if budget < limit {
				limit = budget
			}
			if dec, err := inflate(raw, limit); err == nil {
				raw = dec
			} else {
				offset = end + len("endstream")
				continue
			}
		} else if len(raw) > budget {
			raw = raw[:budget]
		}
		if len(raw) > budget {
			raw = raw[:budget]
		}
		budget -= len(raw)
		if txt := extractText(raw); txt != "" {
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			b.WriteString(txt)
			if len([]rune(b.String())) >= maxChars {
				break
			}
		}
		offset = end + len("endstream")
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	r := []rune(out)
	if len(r) > maxChars {
		out = string(r[:maxChars])
	}
	return out
}

func inflate(raw []byte, limit int) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(io.LimitReader(zr, int64(limit)))
}

func extractText(stream []byte) string {
	var parts []string
	for _, m := range tjRe.FindAllSubmatch(stream, -1) {
		parts = append(parts, unescapePDF(m[1]))
	}
	for _, m := range tjArrRe.FindAllSubmatch(stream, -1) {
		for _, s := range strRe.FindAllSubmatch(m[1], -1) {
			parts = append(parts, unescapePDF(s[1]))
		}
	}
	return strings.Join(parts, " ")
}

func unescapePDF(in []byte) string {
	// UTF-16BE strings start with a BOM.
	if len(in) >= 2 && in[0] == 0xFE && in[1] == 0xFF {
		u := make([]uint16, 0, (len(in)-2)/2)
		for i := 2; i+1 < len(in); i += 2 {
			u = append(u, uint16(in[i])<<8|uint16(in[i+1]))
		}
		return string(utf16.Decode(u))
	}
	var out []rune
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c != '\\' {
			out = append(out, rune(c))
			continue
		}
		i++
		if i >= len(in) {
			break
		}
		switch in[i] {
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case '(', ')', '\\':
			out = append(out, rune(in[i]))
		case '0', '1', '2', '3', '4', '5', '6', '7':
			v := int(in[i] - '0')
			for k := 1; k < 3 && i+1 < len(in) && in[i+1] >= '0' && in[i+1] <= '7'; k++ {
				i++
				v = v*8 + int(in[i]-'0')
			}
			out = append(out, rune(v))
		default:
			out = append(out, rune(in[i]))
		}
	}
	return string(out)
}
