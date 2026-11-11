// Package detect classifies incoming requests as human, bot, sandbox, or
// scanner. It is used to serve a harmless page to non-human visitors so a
// security sandbox or crawler never sees the phishing content, and so their
// traffic is not miscounted as a human click.
package detect

import "strings"

// Verdict classifies a visitor.
type Verdict int

const (
	// Human is a real, interactive visitor.
	Human Verdict = iota
	// Bot is an automated crawler or non-browser HTTP client.
	Bot
	// Sandbox is a security sandbox / headless browser used by mail gateways.
	Sandbox
	// Scanner is an active security scanner.
	Scanner
)

// Classify labels a request from its User-Agent and headers. The rules are
// deliberately conservative: only unmistakable automation is filtered, so a
// real employee using a privacy browser never gets the harmless page.
func Classify(ua string) Verdict {
	ua = strings.ToLower(ua)
	if ua == "" {
		return Bot
	}

	// Active security scanners.
	for _, s := range []string{
		"sqlmap", "nikto", "nessus", "nmap", "masscan", "openvas", "wpscan",
		"acunetix", "burpsuite", "netsparker", "appscan", "dirbuster", "gobuster",
	} {
		if strings.Contains(ua, s) {
			return Scanner
		}
	}

	// Sandbox / headless browser markers.
	for _, s := range []string{
		"phantomjs", "headlesschrome", "headless", "puppeteer", "playwright",
		"selenium", "webdriver", "qtwebengine",
	} {
		if strings.Contains(ua, s) {
			return Sandbox
		}
	}

	// Scripted HTTP clients.
	for _, s := range []string{
		"curl", "wget", "python-requests", "python-urllib", "go-http-client",
		"java/", "libwww-perl", "okhttp", "axios", "node-fetch", "httpx", "aiohttp",
	} {
		if strings.Contains(ua, s) {
			return Bot
		}
	}

	// Known crawlers.
	for _, s := range []string{
		"googlebot", "bingbot", "baiduspider", "yandexbot", "duckduckbot",
		"slurp", "facebookexternalhit", "twitterbot", "applebot",
	} {
		if strings.Contains(ua, s) {
			return Bot
		}
	}

	return Human
}
