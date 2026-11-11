package email

import (
	"html"
	"regexp"
	"strings"
)

var (
	reScriptStyle = regexp.MustCompile(`(?is)<(script|style|head)[^>]*>.*?</(script|style|head)>`)
	reBlockBreak  = regexp.MustCompile(`(?i)</?(p|div|br|tr|li|h[1-6]|table|section|article)[^>]*>`)
	reTag         = regexp.MustCompile(`(?s)<[^>]+>`)
	reSpace       = regexp.MustCompile(`[ \t\f\v]+`)
	reBlank       = regexp.MustCompile(`\n{3,}`)
)

// HTMLToText produces a readable plain-text fallback from an HTML email.
// It is deliberately simple: remove scripts/styles/head, turn block edges into
// newlines, strip remaining tags, decode entities, and collapse whitespace.
func HTMLToText(body string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}
	s := reScriptStyle.ReplaceAllString(body, " ")
	s = reBlockBreak.ReplaceAllString(s, "\n")
	s = reTag.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		line = reSpace.ReplaceAllString(line, " ")
		lines[i] = strings.TrimSpace(line)
	}
	s = strings.Join(lines, "\n")
	s = reBlank.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}

// PrepareHTML adds the compatibility hints that keep an email readable across
// clients: a mobile viewport and an explicit light color scheme, so clients
// that auto-darken email do not invert a page designed for light backgrounds.
// Existing hints are left untouched.
func PrepareHTML(body string) string {
	if strings.TrimSpace(body) == "" {
		return body
	}
	var metas []string
	if !strings.Contains(strings.ToLower(body), `name="viewport"`) && !strings.Contains(strings.ToLower(body), "name='viewport'") {
		metas = append(metas, `<meta name="viewport" content="width=device-width, initial-scale=1">`)
	}
	if !strings.Contains(strings.ToLower(body), "color-scheme") {
		metas = append(metas,
			`<meta name="color-scheme" content="light only">`,
			`<meta name="supported-color-schemes" content="light">`)
	}
	if len(metas) == 0 {
		return body
	}
	inject := strings.Join(metas, "")
	lower := strings.ToLower(body)
	if i := strings.Index(lower, "<head"); i >= 0 {
		if j := strings.Index(lower[i:], ">"); j >= 0 {
			pos := i + j + 1
			return body[:pos] + inject + body[pos:]
		}
	}
	return inject + body
}
