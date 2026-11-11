<p align="center">
  <strong>Questions? Contact the author</strong><br>
  <img src="docs/images/wechat-contact.jpg" width="220" alt="WeChat QR code">
</p>

# PhishTide — Phishing Simulation Platform

[English](README.md) | [简体中文](README.zh-CN.md)

**Docs:** [One-click deployment](docs/en/ONE-CLICK.md) · [UI guide (Chinese, screenshots)](docs/zh-CN/UI-GUIDE.md) · [Configuration](docs/en/CONFIGURATION.md) · [Deployment](docs/en/DEPLOYMENT.md) · [Security](docs/en/SECURITY.md)

> **Read-only repository:** visitors may view, clone and download. Only the owner can push; pull requests from visitors are not accepted.

## Deploy in 3 steps

1. Download `phishsim-oneclick-linux-amd64.tar.gz` (or the arm64 bundle) from [Releases](https://github.com/shangdi-w/PhishTide/releases).
2. Extract: `tar xzf phishsim-oneclick-linux-amd64.tar.gz && cd phishsim-oneclick-linux-amd64`
3. Install: `sudo ./install.sh`

The installer creates a systemd service with SQLite, generates an admin password, opens the firewall port and prints the admin URL. Full beginner guide: [docs/en/ONE-CLICK.md](docs/en/ONE-CLICK.md). The one-click bundle targets Ubuntu/Debian; the other release binaries can be run manually on Linux/Windows.

> **Easiest option:** give a terminal-capable AI agent (Cursor, Codex, or another terminal-capable AI) your server SSH credentials and this repository URL, and ask it to run the one-click installer. Prompt template and safety notes: [docs/en/ONE-CLICK.md §14](docs/en/ONE-CLICK.md#14-let-an-ai-deploy-it-for-you).

A self-hosted phishing simulation platform for **authorized security awareness training and internal phishing drills**. It covers the full loop: email generation, landing-page cloning, credential/form capture, tracking, risk reporting and CSV export.

> **Authorized use only.** Use this software only against people and systems you own or have explicit written permission to test. The authors provide no warranty and accept no liability for misuse. See [SECURITY.md](SECURITY.md).

## Features

- **Email generation** — built-in templates plus Go template variables, rendered per recipient (tracking URL and tracking pixel included).
- **Landing pages** — built-in login templates, or clone a real site: mirror same-origin assets, rewrite form actions to the capture endpoint, render SPAs with a headless browser, and record XHR/fetch JSON so the clone keeps working. A **reverse-proxy mode** forwards the live upstream site (including scripts and APIs) while capturing password submissions locally and answering them without ever logging in upstream.
- **Credential capture** — stores the username, password and **every submitted form field**.
- **Operator console** — campaign stats (sent/opened/clicked/submitted), captured credentials and form data, CSV export.
- **A/B templates** — two email templates per campaign with weighted split; reports break results down by variant.
- **Link policy** — per-campaign link TTL, burn-after-submit links, and IP/CIDR allow/deny lists.
- **Seed delivery** — extra copies to seed mailboxes (A template, untracked) for inbox placement and spam-filter testing.
- **Client compatibility** — injects viewport and light color-scheme meta tags; generates plain text from HTML when missing.
- **Risk reports** — per-recipient and per-department risk scores with a printable HTML report.
- **Send ledger / bounces / suppression** — durable delivery records, DSN bounce polling over IMAP, and a cross-campaign suppression list.
- **Console AI agent (optional)** — an OpenAI-compatible function-calling agent with 57 tools that can operate the platform under operator confirmation gates.

## Architecture

```
cmd/phishsim/main.go            entry point: config, database, TLS, HTTP server
internal/core/                  config, crypto, logbuf, tlsutil, store
internal/services/              analyze, bounce, detect, dnscheck, geoip, hygiene, pdftext, report
internal/features/              clone, email, llm
internal/web/                   public endpoints (/l/, /t/, /submit) + /__admin API
internal/web/static/admin.html  single-page operator console
```

The packages are grouped into four layers:

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

## Requirements

- Go **1.27+** (see `go.mod`); no CGO required.
- SQLite is built in; MySQL 8 is optional.
- Chrome/Chromium on the operator host for headless rendering, screenshots, clone and end-to-end checks.
- An SMTP relay for real sending (the platform can still render emails without one).

## Build and run

```bash
go build -o phishsim ./cmd/phishsim

./phishsim \
  -listen :8443 \
  -data ./data \
  -admin-user admin \
  -admin-pass 'use-a-long-random-password' \
  -public-url https://phish.example.com
```

Open `https://host:8443/__admin`; unauthenticated requests redirect to `/__admin/login`. The listener uses TLS only: a self-signed certificate is generated on first start (add it to your trust store, or terminate TLS in nginx/Caddy with a real certificate).

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

**One-click Ubuntu install:** download the bundle, extract it, and run `sudo ./install.sh`. It installs a systemd service with SQLite, generates a random admin password, opens the firewall port, and prints the admin URL. See [deploy/oneclick/README.md](deploy/oneclick/README.md).

Verify with `sha256sum -c SHA256SUMS`. Reproduce them with `./scripts/build-release.sh 0.1.0`; see [docs/en/BUILD.md](docs/en/BUILD.md).

### Admin login

Pick one of:

```bash
-admin-pass 'plaintext'          # or PHISH_ADMIN_PASS
-admin-pass-hash '<bcrypt hash>' # or PHISH_ADMIN_PASS_HASH, highest priority
-admin-key '<random string>'     # when no password is set, the key doubles as the password
```

Generate a bcrypt hash: `./phishsim -hash-pass 'your password'`.

Successful login sets an `HttpOnly; Secure; SameSite=Strict` signed session cookie. Five failed attempts from one IP within 15 minutes lock that IP for 15 minutes. Changing the password invalidates every existing session.

### Runtime settings

Console → **Settings → Public URL** edits the base URL used in generated links. It is stored in `app_settings`, takes effect immediately, and falls back to `-public-url` / `PHISH_PUBLIC_URL` when cleared. This is the setting to change when you move the platform to a new server, IP or domain; no restart is required for link generation. TLS certificates and the reverse proxy still need to match the new address.

## Configuration

Full flag and environment reference: [docs/en/CONFIGURATION.md](docs/en/CONFIGURATION.md).

Common security knobs:

```bash
-trusted-proxies 127.0.0.1/32   # only these proxies may set X-Forwarded-For
-clone-deny-private             # refuse clone/proxy URLs resolving to private/loopback addresses
-retention-days 30              # purge submissions/events older than N days (0 disables)
-max-send-targets 500           # per-send recipient cap (0 disables)
PHISH_MASK_PASSWORDS=true       # mask passwords in the console and CSV
```

Optional SMTP:

```bash
./phishsim -smtp-host smtp.example.com -smtp-port 587 \
  -smtp-user user -smtp-pass pass -smtp-tls ...
```

Without SMTP the platform still renders and previews emails.

## Campaign workflow

1. Create a **target group** (manually, CSV import, or the console agent).
2. Create an **email template** and a **landing page** (template, clone, or reverse proxy).
3. Create a **campaign** binding template, page, group(s), and a sending profile.
4. **Dry run** to render previews and validate the page, recipients and sender.
5. **Send** (two-phase: prepare, then operator confirmation).
6. Watch opens/clicks/submissions, run a **risk report**, export CSV.

## Tracking URL structure

| Path | Purpose |
| --- | --- |
| `/l/<token>/` | landing page (first visit records a click); proxy pages 302 to `/l/<token>/px/<upstream-path>` |
| `/l/<token>/submit` | form submission → capture credentials and all fields |
| `/l/<token>/assets/<...>` | mirrored clone assets |
| `/l/<token>/px/<upstream-path>` | reverse-proxy live forwarding (rewrites same-origin references, script requests, cookies) |
| `/t/<token>` | tracking pixel (records an open) |
| `/r/<token>` / `/u/<token>` | report / unsubscribe |

IP deny (or a non-matching allow list) returns 403; expired or one-time-used links return 410.

## Email template variables

`{{.FirstName}}` `{{.LastName}}` `{{.Email}}` `{{.Position}}` `{{.TrackingURL}}` `{{.TrackingPixel}}` `{{.FromName}}` `{{.FromEmail}}`

## Cloning and reverse proxy

| Mode | How it works | Best for | Trade-off |
| --- | --- | --- | --- |
| Clone (default) | headless render → HTML snapshot + same-origin assets; browser network capture mirrors lazy chunks and XHR/fetch JSON, replayed by an SPA shim | most sites; works offline after cloning | not a frame-perfect reproduction; heavy real-time interactions may degrade |
| Clone (static form) | strip JS, keep HTML/CSS, submit to the platform | static/SSR login pages | JS-rendered login widgets disappear |
| Reverse proxy | no snapshot; forward upstream live and rewrite same-origin references, script requests, cookie scope and redirects | complex SPAs, SSO, full login flows | upstream must stay online; the platform is a man-in-the-middle |

Password-bearing submissions are **never forwarded upstream**; they are recorded and answered locally (a configurable number of failures can return 401), so a drill never performs a real login.

Known limits: WebSocket upgrades and service workers are not proxied; direct `location=` jumps to absolute paths can escape the prefix; only text responses are rewritten (32 MB cap); authenticated-only pages are only visible anonymously.

## Credential extraction

The first non-empty `username/user/email/login/account/name` field becomes the username; the first non-empty `password/pass/pwd/passwd` field becomes the password. All other fields are preserved in `fields` and visible in the console/CSV.

## Console AI agent (optional)

The console has an OpenAI-compatible chat agent with function calling. Configure it in **Settings → Model** or at startup:

Once configured, you can ask the agent to generate emails and landing pages, create or update sending profiles, create campaigns, dry-run, send (with your confirmation), diagnose failures, poll bounces and produce risk reports. A real end-to-end AI send test with screenshots is documented in [docs/zh-CN/UI-GUIDE.md §21](docs/zh-CN/UI-GUIDE.md#21-ai-一键发送实战).

```bash
PHISH_LLM_BASE_URL=https://api.deepseek.com/v1 \
PHISH_LLM_KEY=your-key PHISH_LLM_MODEL=deepseek-chat ./phishsim ...
```

Highlights:

- **57 tools** covering groups, templates, attachments, pages, cloning/proxying, validation, screenshots, version history, sending profiles, campaigns, dry runs, risk reports, send ledger/status, bounces, suppression, global search, GeoIP, todos, plans, diagnostics, background jobs, subagents and long-term memory.
- **Self-check loop** — `validate_page` checks form action, `__SUBMIT_URL__`, inputs, password fields, external resources and capture toggles; `preview_page` renders a screenshot; `dry_run_campaign` checks templates/pages/recipients/sender and SPF/DKIM/DMARC.
- **End-to-end check** — `e2e_check_page` creates throwaway objects, serves the page in-process and drives a real browser through the capture path; cleans up afterwards.
- **Write gates** — overwriting an existing template/page/profile, high-risk writes, tainted sessions and multi-step plans require operator confirmation. Approved calls replay the model's exact original arguments.
- **Two-phase send** — `send_campaign` only prepares; the operator must click “Confirm send”.
- **Background jobs / subagents / todos / memory** — detached jobs resume after restart; up to 4 read-only subagents; per-session checklist; cross-session memory.
- **Safety** — external content is marked `untrusted:true`; sessions that read it gate all writes; fetch/proxy can be allow-listed with `PHISH_FETCH_ALLOWLIST`; credentials are redacted from logs.

Full agent reference: [docs/en/AGENT.md](docs/en/AGENT.md).

## API

Console API requires a session cookie or `Authorization: Bearer <admin-key>` (query-string keys are rejected). The full endpoint list and curl examples are in [docs/en/API.md](docs/en/API.md). A generated OpenAPI description is served at `GET /__admin/api/openapi.yaml` and is viewable from the console.

## Deployment

See [docs/en/DEPLOYMENT.md](docs/en/DEPLOYMENT.md) for single-binary/SQLite, MySQL, TLS, nginx/Caddy, SSH tunnels, systemd, backups and upgrades.

## Security

See [docs/en/SECURITY.md](docs/en/SECURITY.md) and [SECURITY.md](SECURITY.md). Key points:

- Keep `/__admin` off the public internet (reverse-proxy deny, VPN, or SSH tunnel).
- Enable `-clone-deny-private` when clone/proxy URLs are not fully trusted.
- Use a least-privilege database account, a real certificate, and strong admin credentials.
- Landing pages and the admin console share an origin; do not browse test links while logged in to the console. Use a separate browser profile or host for drills.

## Development

```bash
go vet ./...
go test ./...
go build ./...
```

The test suite is offline and deterministic (LLM calls are stubbed). `scripts/clone_probe` is a developer probe for inspecting a clone's assets/APIs. See [CONTRIBUTING.md](CONTRIBUTING.md).

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
