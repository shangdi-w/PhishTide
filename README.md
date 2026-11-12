<p align="center">
  <strong>Questions? Contact the author</strong><br>
  <img src="docs/images/wechat-contact.jpg" width="220" alt="WeChat QR code">
</p>

# PhishTide — Phishing Simulation Platform

[English](README.md) | [简体中文](README.zh-CN.md)

A self-hosted platform for **authorized phishing simulations and security-awareness training**. It covers the full loop: email generation → landing page → tracking → credential/form capture → risk reporting and CSV export.

> **Authorized use only.** Use this software only against people and systems you own or have explicit written permission to test. The authors provide no warranty and accept no liability for misuse. See [SECURITY.md](SECURITY.md).
>
> **Read-only repository:** visitors may view, clone and download. Only the owner can push; pull requests from visitors are not accepted.

**Docs:** [Docker quick start](docs/en/DOCKER.md) · [One-click deployment](docs/en/ONE-CLICK.md) · [Console manual (Chinese, screenshots)](docs/zh-CN/UI-GUIDE.md) · [Configuration](docs/en/CONFIGURATION.md) · [Deployment](docs/en/DEPLOYMENT.md) · [Agent](docs/en/AGENT.md) · [API](docs/en/API.md) · [Troubleshooting](docs/en/TROUBLESHOOTING.md)

## Quick start

### Option A — Docker (recommended)

Chromium and CJK fonts included; works on Linux, macOS and Windows (Docker Desktop):

```bash
git clone https://github.com/shangdi-w/PhishTide.git && cd PhishTide
./deploy/docker/quickstart.sh      # or --binary ./phishsim-linux-amd64
```

The script generates an admin password, builds the image and starts a container with a data volume. Mirrors, backup, upgrade and troubleshooting: [docs/en/DOCKER.md](docs/en/DOCKER.md).

### Option B — one-click bundle (Ubuntu/Debian)

1. Download `phishsim-oneclick-linux-amd64.tar.gz` (or the arm64 bundle) from [Releases](https://github.com/shangdi-w/PhishTide/releases).
2. Extract: `tar xzf phishsim-oneclick-linux-amd64.tar.gz && cd phishsim-oneclick-linux-amd64`
3. Install: `sudo ./install.sh`

The installer creates a systemd service with SQLite, generates an admin password, opens the firewall port and prints the admin URL. Beginner walkthrough: [docs/en/ONE-CLICK.md](docs/en/ONE-CLICK.md). Bundle reference: [deploy/oneclick/README.md](deploy/oneclick/README.md).

> **Shortcut:** give a terminal-capable AI agent (Cursor, Codex, or another terminal-capable AI) your server SSH credentials and this repository URL, and ask it to run the installer. Prompt template and safety notes: [docs/en/ONE-CLICK.md §14](docs/en/ONE-CLICK.md#14-let-an-ai-deploy-it-for-you).

### Option C — build from source

```bash
git clone https://github.com/shangdi-w/PhishTide.git && cd PhishTide
go build -o phishsim ./cmd/phishsim

./phishsim \
  -listen :8443 \
  -data ./data \
  -admin-user admin \
  -admin-pass 'use-a-long-random-password' \
  -public-url https://phish.example.com
```

Open `https://host:8443/__admin`; unauthenticated requests redirect to `/__admin/login`. The listener is TLS-only: a self-signed certificate is generated on first start (add it to your trust store, or terminate TLS in nginx/Caddy with a real certificate). Requires Go **1.27+**; Chrome/Chromium is needed on the operator host for clone, screenshots and end-to-end checks.

## What it does

```
targets ──► campaign ──► email template ──► SMTP ──► recipient inbox
                                                         │
                        tracking pixel (/t/) and link (/l/)│
                                                         ▼
                                              landing page (template / clone / proxy)
                                                         │
                                     form submit (/l/<token>/submit)
                                                         ▼
                                    captured fields ──► console · CSV · risk report
```

## Features

**Content**

- Email templates with per-recipient Go-template variables, tracking URL/pixel, plain-text fallback and client-compatibility meta tags.
- Landing pages: built-in login templates; site cloning (headless render, same-origin assets, XHR/fetch replay for SPAs); static-form mode; and **reverse-proxy mode** that forwards the live site while capturing passwords locally and never forwarding them upstream.

**Sending and policy**

- A/B templates with a weighted split and per-variant reporting.
- Per-campaign link TTL, burn-after-submit links, IP/CIDR allow/deny lists, seed delivery.
- Suppression list, per-recipient failure classification with retry and circuit breaker, IMAP DSN bounce recovery, and a durable send ledger that survives campaign deletion.

**Capture and reporting**

- Captures the username, password and **every submitted form field**; encrypted at rest (AES-256-GCM); CSV export with UTF-8 BOM and formula-injection neutralization.
- Risk reports per recipient and per department, with a printable HTML view.

**Platform**

- Operator console: campaigns, groups, templates, pages, attachments, submissions, logs, global search and settings.
- Optional OpenAI-compatible **console AI agent** with 57 tools, confirmation gates, background jobs, read-only subagents, todos and long-term memory.
- SQLite by default, MySQL 8 optional; passive offline GeoIP; recipient-list hygiene (MX/role/disposable checks); SPF/DKIM/DMARC preflight.
- Prometheus `/metrics`, JSON log tee, CI on every push.

**Security**

- bcrypt/plaintext/admin-key login, HMAC-signed `HttpOnly; Secure; SameSite=Strict` sessions, per-IP lockout and session invalidation on password change.
- CSRF protection, trusted-proxy-only `X-Forwarded-For`, CSP/HSTS/frame/nosniff/no-referrer, request body/field/upload caps.
- Optional SSRF guard (`-clone-deny-private`), prompt-injection containment, and sandboxed `/p/` previews.

## Console

The operator console is a single embedded SPA at `/__admin`. A screenshot-by-screenshot manual (Chinese) covers every screen, setting and the end-to-end AI send demo: [docs/zh-CN/UI-GUIDE.md](docs/zh-CN/UI-GUIDE.md).

### Admin login

Pick one of:

```bash
-admin-pass 'plaintext'          # or PHISH_ADMIN_PASS
-admin-pass-hash '<bcrypt hash>' # or PHISH_ADMIN_PASS_HASH, highest priority
-admin-key '<random string>'     # when no password is set, the key doubles as the password
```

Generate a bcrypt hash: `./phishsim -hash-pass 'your password'`. Successful login sets a signed session cookie; five failed attempts from one IP within 15 minutes lock that IP for 15 minutes; changing the password invalidates every existing session.

### Runtime settings

Console → **Settings → Public URL** edits the base URL used in generated links. It is stored in `app_settings`, takes effect immediately, and falls back to `-public-url` / `PHISH_PUBLIC_URL` when cleared. Change it when moving to a new server, IP or domain — no restart is needed for link generation. TLS certificates and the reverse proxy still need to match the new address.

## Architecture

```
cmd/phishsim/main.go            entry point: config, database, TLS, HTTP server
internal/core/                  config, crypto, logbuf, tlsutil, store
internal/services/              analyze, bounce, detect, dnscheck, geoip, hygiene, pdftext, report
internal/features/              clone, email, llm
internal/web/                   public endpoints (/l/, /t/, /submit) + /__admin API
internal/web/static/admin.html  single-page operator console
```

Four layers:

- **core** — infrastructure: configuration, crypto, persistence, logging, TLS.
- **services** — domain logic: analysis, reporting, hygiene, GeoIP, bounce/DSN, PDF text, detection, DNS checks.
- **features** — integrations/content: site cloning, email rendering/SMTP, LLM client.
- **web** — delivery: HTTP routing, public portal, admin API, console agent, embedded SPA.

## Data model (SQLite / MySQL)

| Table | Purpose |
| --- | --- |
| `campaigns` | campaign: email template + landing page, optional B template/AB split, link policy, IP lists, seed addresses |
| `targets` | recipients (per-target token; sent/opened/clicked/submitted state; department/position) |
| `email_templates` | subject / HTML / text templates |
| `landing_pages` + `page_assets` | landing pages (template or clone) and mirrored assets |
| `events` | tracking events (opened/clicked/submitted, plus behavior events) |
| `submissions` | captured forms (username/password + all fields JSON) |
| `send_ledger` | durable delivery ledger, survives campaign deletion (Message-ID included) |
| `bounces` / `send_failures` | DSN bounces and per-recipient delivery diagnostics |
| `suppressions` | cross-campaign do-not-send list |
| `content_versions` | version history for templates and landing pages (last 20 per object) |

## Configuration

Three layers: built-in defaults → `PHISH_*` environment variables → command-line flags (highest priority). Console settings (public URL, model, bounce mailbox, log retention, background) live in `app_settings` and survive restarts.

Common settings:

| Flag / variable | Default | Purpose |
| --- | --- | --- |
| `-listen` / `PHISH_LISTEN` | `:8443` | HTTP listen address; use `127.0.0.1:8443` behind a proxy. |
| `-data` / `PHISH_DATA_DIR` | `data` | SQLite DB, secret key, TLS certs, background image. |
| `-public-url` / `PHISH_PUBLIC_URL` | derived | External base URL used in generated links. |
| `-admin-user` / `-admin-pass` / `-admin-key` | `admin` / empty / empty | Console credentials. |
| `-trusted-proxies` | loopback | CIDRs whose `X-Forwarded-For` is honoured. |
| `-clone-deny-private` | `false` | Refuse clone/proxy URLs resolving to private/loopback addresses. |
| `-retention-days` | `30` | Purge submissions/events older than N days; `0` disables. |
| `-max-send-targets` | `500` | Max pending recipients per send; `0` disables. |
| `-fail-attempts` | `2` | Wrong-password prompts before redirecting; `0` redirects immediately. |
| `PHISH_MASK_PASSWORDS` | `false` | Mask passwords in the console and CSV (first two characters kept). |
| `PHISH_DB_DRIVER` / `PHISH_DB_DSN` | `sqlite` / empty | `mysql` switches to MySQL 8. |
| `PHISH_SECRET_KEY` | generated | 64-hex-char AES-256 key; otherwise `<data>/secret.key`. |

Full reference — every flag, environment variable, limit and console setting: [docs/en/CONFIGURATION.md](docs/en/CONFIGURATION.md). SMTP is optional: without it the platform still renders and previews emails.

### Email template variables

`{{.FirstName}}` `{{.LastName}}` `{{.Email}}` `{{.Position}}` `{{.TrackingURL}}` `{{.TrackingPixel}}` `{{.FromName}}` `{{.FromEmail}}`

### Tracking URLs

| Path | Purpose |
| --- | --- |
| `/l/<token>/` | landing page (first visit records a click); proxy pages 302 to `/l/<token>/px/<upstream-path>` |
| `/l/<token>/submit` | form submission → capture credentials and all fields |
| `/l/<token>/assets/<...>` | mirrored clone assets |
| `/l/<token>/px/<upstream-path>` | reverse-proxy live forwarding (rewrites same-origin references, script requests, cookies) |
| `/t/<token>` | tracking pixel (records an open) |
| `/r/<token>` / `/u/<token>` | report / unsubscribe |

IP deny (or a non-matching allow list) returns 403; expired or one-time-used links return 410.

## Cloning and reverse proxy

| Mode | How it works | Best for | Trade-off |
| --- | --- | --- | --- |
| Clone (default) | headless render → HTML snapshot + same-origin assets; browser network capture mirrors lazy chunks and XHR/fetch JSON, replayed by an SPA shim | most sites; works offline after cloning | not a frame-perfect reproduction; heavy real-time interactions may degrade |
| Clone (static form) | strip JS, keep HTML/CSS, submit to the platform | static/SSR login pages | JS-rendered login widgets disappear |
| Reverse proxy | no snapshot; forward upstream live and rewrite same-origin references, script requests, cookie scope and redirects | complex SPAs, SSO, full login flows | upstream must stay online; the platform is a man-in-the-middle |

Password-bearing submissions are **never forwarded upstream**; they are recorded and answered locally (a configurable number of failures can return 401), so a drill never performs a real login. Credential extraction: the first non-empty `username/user/email/login/account/name` field becomes the username, the first non-empty `password/pass/pwd/passwd` field becomes the password, and every other field is preserved.

Known limits: WebSocket upgrades and service workers are not proxied; direct `location=` jumps to absolute paths can escape the prefix; only text responses are rewritten (32 MB cap); authenticated-only pages are only visible anonymously.

## Console AI agent (optional)

The console has an OpenAI-compatible function-calling agent. Configure it in **Settings → Model** or at startup:

```bash
PHISH_LLM_BASE_URL=https://api.deepseek.com/v1 \
PHISH_LLM_KEY=your-key PHISH_LLM_MODEL=deepseek-chat ./phishsim ...
```

Once configured, ask the agent to generate emails and landing pages, create or update sending profiles, create campaigns, dry-run, send (with your confirmation), diagnose failures, poll bounces and produce risk reports. A real end-to-end AI send test with screenshots is documented in [docs/zh-CN/UI-GUIDE.md §21](docs/zh-CN/UI-GUIDE.md#21-ai-一键发送实战).

Highlights:

- **57 tools** covering groups, templates, attachments, pages, cloning/proxying, validation, screenshots, version history, sending profiles, campaigns, dry runs, risk reports, send ledger/status, bounces, suppression, global search, GeoIP, todos, plans, diagnostics, background jobs, subagents and long-term memory.
- **Self-check loop** — `validate_page`, `preview_page`, `dry_run_campaign` and `e2e_check_page` keep landing pages and campaigns verified before anything is sent.
- **Write gates** — overwrites, high-risk writes, tainted sessions and multi-step plans require operator confirmation; approved calls replay the model's exact original arguments.
- **Two-phase send** — `send_campaign` only prepares; the operator clicks “Confirm send”.
- **Background jobs / subagents / todos / memory** — detached jobs resume after restart; up to 4 read-only subagents; per-session checklist; cross-session memory.

Full agent reference: [docs/en/AGENT.md](docs/en/AGENT.md).

## API

The console API requires a session cookie or `Authorization: Bearer <admin-key>` (query-string keys are rejected). The full endpoint list, SSE frames and curl examples are in [docs/en/API.md](docs/en/API.md). A generated OpenAPI description is served at `GET /__admin/api/openapi.yaml` and is viewable from the console.

## Deployment

See [docs/en/DEPLOYMENT.md](docs/en/DEPLOYMENT.md) for single-binary/SQLite, MySQL, TLS, nginx/Caddy, SSH tunnels, systemd, backups and upgrades. Keep `/__admin` off the public internet (reverse-proxy deny, VPN or SSH tunnel), enable `-clone-deny-private` when clone/proxy URLs are not fully trusted, and use a least-privilege database account with real certificates.

Landing pages and the admin console share an origin: do not browse test links while logged in to the console. See [docs/en/SECURITY.md](docs/en/SECURITY.md) for the threat model, residual risks and hardening checklist.

## Development

```bash
go vet ./...
go test ./...
go build ./...
```

The test suite is offline and deterministic (LLM calls are stubbed). `scripts/clone_probe` is a developer probe for inspecting a clone's assets/APIs. See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/en/BUILD.md](docs/en/BUILD.md).

### Prebuilt binaries

GitHub Releases ships labeled, statically linked binaries (CGO disabled, no glibc dependency):

| Asset | Platform |
| --- | --- |
| `phishsim-linux-amd64` | Ubuntu 20.04+/Debian 11+ x86_64 |
| `phishsim-linux-arm64` | Ubuntu 22.04+ ARM64 (Graviton/Ampere) |
| `phishsim-windows-amd64.exe` | Windows 10/11 x64 |
| `phishsim-oneclick-linux-amd64.tar.gz` | Ubuntu/Debian x86_64 one-click bundle |
| `phishsim-oneclick-linux-arm64.tar.gz` | Ubuntu/Debian ARM64 one-click bundle |
| `SHA256SUMS` | checksums for all assets |

Reproduce them with `./scripts/build-release.sh 0.1.0` and verify with `sha256sum -c SHA256SUMS`.

## Documentation

| English | 中文 |
| --- | --- |
| [Docs index](docs/README.md) | [文档索引](docs/README.md) |
| [Docker](docs/en/DOCKER.md) | [Docker](docs/zh-CN/DOCKER.md) |
| [One-click deployment](docs/en/ONE-CLICK.md) | [一键部署](docs/zh-CN/ONE-CLICK.md) |
| [Configuration](docs/en/CONFIGURATION.md) | [配置](docs/zh-CN/CONFIGURATION.md) |
| [Deployment](docs/en/DEPLOYMENT.md) | [部署](docs/zh-CN/DEPLOYMENT.md) |
| [Build](docs/en/BUILD.md) | [编译](docs/zh-CN/BUILD.md) |
| [Architecture](docs/en/ARCHITECTURE.md) | [架构](docs/zh-CN/ARCHITECTURE.md) |
| [Console agent](docs/en/AGENT.md) | [控制台 Agent](docs/zh-CN/AGENT.md) |
| [API](docs/en/API.md) | [API](docs/zh-CN/API.md) |
| [Security](docs/en/SECURITY.md) | [安全](docs/zh-CN/SECURITY.md) |
| [Troubleshooting](docs/en/TROUBLESHOOTING.md) | [排障](docs/zh-CN/TROUBLESHOOTING.md) |
| — | [后台功能图解](docs/zh-CN/UI-GUIDE.md) |

## Project layout

```
cmd/phishsim/            entry point
internal/
  core/                  config crypto logbuf tlsutil store
  services/              analyze bounce detect dnscheck geoip hygiene pdftext report
  features/              clone email llm
  web/                   HTTP/public portal/admin API/agent + embedded console
deploy/                  generic deployment templates (Caddy, frp, backups, env example)
docs/                    English and Chinese manuals
scripts/                 clone_probe, fetch_geoip.sh, build-release.sh
```

## License

No license is granted. The source is published for viewing and downloading; all rights are reserved by the author. Third-party front-end assets under `internal/web/static/vendor/` (Vue, Element Plus) retain their own licenses.
