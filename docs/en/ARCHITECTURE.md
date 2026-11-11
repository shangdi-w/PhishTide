# Architecture

PhishTide is a single Go binary with an embedded operator SPA. There is no separate front-end build step and no Node.js runtime at deploy time.

## Process model

```
cmd/phishsim/main.go
  ├─ config.FromEnv + flags
  ├─ store.Open (SQLite) or store.OpenMySQL (MySQL)
  ├─ optional offline GeoIP load
  ├─ log ring buffer + optional JSON log file
  ├─ web.Server (all HTTP handlers)
  ├─ scheduler goroutine (due sends + auto bounce poll)
  ├─ retention goroutine (daily purge)
  ├─ agent worker goroutines (background jobs)
  └─ http.Server (TLS only)
```

The HTTP surface is one listener. Public routes and `/__admin` share it; deploy behind a reverse proxy if you need to hide the console by path or source IP.

## Package responsibilities

Packages are grouped into four layers: **core** (infrastructure), **services** (domain logic), **features** (integrations/content) and **web** (delivery).

| Package | Responsibility |
| --- | --- |
| `internal/core/config` | Defaults, `PHISH_*` env loading, flags, public URL derivation |
| `internal/core/store` | SQL schema/migrations, all persistence methods, dialect helpers for SQLite/MySQL |
| `internal/core/crypto` | AES-256-GCM helpers and key file loading |
| `internal/features/clone` | HTTP/browser cloning, asset mirroring, HTML/CSS rewriting, SPA shim, proxy rewriting, screenshots, form submission used by e2e checks |
| `internal/features/email` | Go-template rendering, MIME construction, SMTP transport, failure classification |
| `internal/web` | Routing, public handlers, admin API, agent loop/tools, sending pipeline, sessions/auth, settings |
| `internal/services/analyze` | Cached platform snapshot and text summary |
| `internal/services/report` | Per-user/department risk scoring and printable HTML |
| `internal/services/hygiene` | Recipient list audit (syntax, duplicates, role mailboxes, disposable domains, MX) |
| `internal/services/geoip` | Offline ip2asn IPv4 lookup |
| `internal/services/bounce` | Minimal IMAP client and RFC 3464 DSN parser |
| `internal/services/pdftext` | Dependency-free PDF text extraction for uploads |
| `internal/services/detect` | User-Agent classification (human/bot/sandbox/scanner) |
| `internal/services/dnscheck` | SPF/DKIM/DMARC lookups |
| `internal/core/logbuf` | Bounded in-memory `slog` handler with an optional sink |
| `internal/core/tlsutil` | Self-signed certificate generation/loading |

## Request flows

### Landing page and capture

```
GET /l/<rid>/            → ResultByRid → GetCampaign → GetPage
                           → IP/link policy → bot filter → render placeholders
GET /l/<rid>/assets/...  → exact page_assets lookup
POST/GET /l/<rid>/submit → parse form/json → cap fields → RecordSubmission
                           → optional wrong-password retry → redirect
```

Capture is skipped for terminated campaigns, non-human UAs and cross-site requests. Passwords and the full field map are sealed with AES-GCM when a secret key exists.

### Tracking, report, unsubscribe, behavior

- `GET /t/<rid>` writes a 1×1 GIF and records the first human open.
- `GET /r/<rid>` records a report; `GET /u/<rid>` records unsubscribe and adds the address to the suppression list.
- `GET /b/<rid>/<kind>` records client-side behavior events (page load, dwell, click, focus, submit attempt).

### Clone

```
admin clone / clone_site
  → clone.CloneWithBrowser (preferred) or clone.Clone (fallback)
  → mirror same-origin assets + browser network captures
  → rewrite references and form actions
  → store landing_pages + page_assets
```

### Reverse proxy

```
GET /l/<rid>/            → 302 /l/<rid>/px/<upstream-path>
GET /l/<rid>/px/<path>   → proxyForward
  → body sniff for password fields
      ├─ password present → RecordSubmission + local fake response (never upstream)
      └─ otherwise        → forward request, rewrite HTML/CSS/redirect/cookies
```

### Send pipeline

```
admin send / scheduler / agent confirmation
  → load campaign + template(s) + attachments + profile
  → build pending recipients, apply suppression + max-send cap
  → render per recipient → email.Build → deliver (retry policy)
  → record send_ledger + send_failures; trip circuit breaker on global errors
```

### Agent loop

```
chat/stream (session_id)
  → load history + repair dangling tool-call pairs + trim context
  → system prompt (tools, memories, todo list)
  → for each round:
       ChatWithTools(stream)
       → execute tool calls (parallel read-only, sequential writes)
       → write gates / pending confirmation
       → persist assistant/tool turns
  → stream deltas/tool events/confirmations/done
```

### Background jobs

`agent_jobs` is a durable queue. Workers claim queued jobs, run the same loop detached from HTTP, retry once, support `run_at` scheduling, and resume after operator confirmation. A per-session lock prevents an interactive turn and a background job from interleaving.

## Data and migrations

- SQLite: one file (`<data>/phishsim.db`), WAL mode, single connection.
- MySQL: `internal/core/store/db.go` contains the DDL; additive migrations tolerate duplicate-column errors.
- Every template/page write records a `content_versions` snapshot (last 20).
- Captured secrets are encrypted at rest; SMTP/LLM/IMAP credentials are sealed in settings.

## Concurrency

- Per-session agent lock (`runMu`).
- Read-only tool calls within one round run concurrently; writes stay ordered.
- Scheduler and bounce poller are serialized; bounce polling is off the scheduler goroutine.
- Log persistence uses a bounded channel and drops rather than blocking.
- Session cookies are stateless HMAC tokens; changing the password changes the signing key.

## Extension points

- Add an agent tool in `internal/web/tools_registry.go` and bind it in `executeTool` (`agent.go`).
- Add a setting in `internal/web/settings.go` (load/save/JSON) and the console form.
- Add a store method in `internal/core/store` with both SQLite and MySQL SQL through `s.sql(...)`.
- Add a public route in `serveHTTP` (`server.go`) or an admin route in `adminRoute`.
