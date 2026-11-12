# Changelog

## 2026-11-12 — Documentation restructure

- Reorganized `README.md` and `README.zh-CN.md` around one mirrored outline: quick start (Docker / one-click / source) → what it does → features → console → architecture → data model → configuration → cloning → agent → API → deployment → development → docs index.
- Deep agent operational details stay in `docs/*/AGENT.md`; both READMEs now link there instead of duplicating the full reference.
- Added `-version` to the flag tables in `docs/en/CONFIGURATION.md` and `docs/zh-CN/CONFIGURATION.md`.
- Embedded the missing AI-chat opening screenshot (`24a-ai-chat-top.png`) in the console guide.
- Re-verified: every internal link and anchor, `go build`, `go vet`, `go test ./...`, and the advertised 57-tool count against `internal/web/tools_registry.go`.

## 2026-11-10 — Initial open-source release

### Platform

- Email templates with per-recipient Go template variables, tracking pixel and tracking URL.
- Built-in landing pages, site cloning (headless browser + static fallback), SPA network capture and replay, and reverse-proxy landing pages.
- Credential/form capture with all submitted fields.
- Campaigns with A/B templates, link TTL, burn-after-submit links, IP allow/deny lists and seed delivery.
- Operator console: campaign stats, submissions, CSV export, risk reports, global search, suppression list.
- Send ledger (survives campaign deletion), per-recipient failure diagnostics/circuit breaker, IMAP DSN bounce recovery.
- Offline GeoIP labels, recipient list hygiene (MX/role/disposable checks), SPF/DKIM/DMARC checks.
- Optional OpenAI-compatible console agent with 57 tools, confirmation gates, background jobs, subagents, todos and long-term memory.

### Security hardening in this release

- Console login with bcrypt/plaintext/admin key, HMAC-signed `HttpOnly; Secure; SameSite=Strict` sessions, per-IP lockout, password-change session invalidation.
- CSRF protection for cookie-authenticated unsafe requests; query-string admin keys rejected.
- Trusted-proxy-only `X-Forwarded-For` handling.
- CSV formula-injection neutralization and UTF-8 BOM.
- Request body/field/upload caps.
- CSP/HSTS/frame/nosniff/no-referrer headers on the console.
- AES-256-GCM at-rest encryption for submission passwords/fields, payload attachments, SMTP/LLM/IMAP credentials.
- Optional SSRF guard (`-clone-deny-private`) for clone/proxy/fetch.
- Prompt-injection containment: untrusted-content marking, session tainting, write gates, exact-argument confirmation replay.
- Sandboxed `/p/` previews (`script-src 'none'`) so cloned markup cannot call admin APIs with the operator's cookie.
- IMAP command CRLF folding; plaintext-IMAP remote credential refusal.
- Constant-time metrics-token comparison; long SSE streams no longer cut by the server write timeout.
- Runtime **Public URL** setting (Settings → Public URL), stored in `app_settings`, no restart required.

### Build and release

- Added `-version` (build-time version via `-ldflags "-X main.version=..."`).
- Added `scripts/build-release.sh` producing labeled static binaries:
  `phishsim-linux-amd64` (Ubuntu/Debian x86_64), `phishsim-linux-arm64` (Ubuntu ARM64), `phishsim-windows-amd64.exe` (Windows x64), plus `SHA256SUMS`.
- Prebuilt binaries are published as GitHub Release assets, not committed to git history.
- Added English and Chinese build/deployment docs, including Ubuntu single-server instructions.
- Added one-click Ubuntu/Debian bundles (`phishsim-oneclick-linux-amd64.tar.gz`, `-arm64`): `install.sh` sets up the user, systemd service, SQLite data, random admin password, firewall port and prints the admin URL; `uninstall.sh` removes it.

### Housekeeping

- Removed unused admin endpoints (`/api/chat` non-stream, `/api/submissions`, `/api/llm/usage`) and dead code (unused TLS SNI/mTLS helpers, unused store/page helpers, unused clone result fields).
- Unified branding to PhishTide; cleaned honeypot/decoy wording.
- Added `.gitignore`, `deploy/phishsim.env.example`, English and Chinese manuals, architecture/deployment/configuration/agent/API/security/troubleshooting docs.
- Sanitized the open-source package: no databases, keys, certificates, logs, screenshots, real IPs, SSH tunnels or frp tokens.

### Known limitations

- No built-in DKIM signing, scanned-PDF OCR, DNS-01 certificate automation or provider log reconciliation.
- Landing pages and the admin console share an origin; see `docs/en/SECURITY.md` (residual risks).
- No license is granted; the source is published for viewing and downloading only.
