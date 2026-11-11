# Configuration

Configuration comes from three layers:

1. built-in defaults,
2. `PHISH_*` environment variables,
3. command-line flags (highest priority).

Runtime settings edited in the console (public URL, LLM, bounce mailbox, log retention, background) are stored in the `app_settings` table and survive restarts.

## Command-line flags

| Flag | Default | Description |
| --- | --- | --- |
| `-listen` | `:8443` | HTTP listen address. Use `127.0.0.1:8443` behind a reverse proxy. |
| `-data` | `data` | Data directory: SQLite DB, secret key, TLS certs, background image. |
| `-public-url` | derived from `-listen` | Public base URL used in generated links. Must be the external address when behind a proxy. |
| `-admin-key` | empty | Bearer key for the admin API. When no password is set, it also works as the login password. Empty disables key auth. |
| `-admin-user` | `admin` | Console username. |
| `-admin-pass` | empty | Console plaintext password. |
| `-admin-pass-hash` | empty | bcrypt hash; takes precedence over `-admin-pass`. |
| `-trusted-proxies` | `127.0.0.1/32,::1/128` | CIDRs whose `X-Forwarded-For` is honoured. |
| `-clone-deny-private` | `false` | Refuse clone/proxy URLs resolving to private, loopback or link-local addresses. |
| `-geoip-db` | auto-detect in data dir | Offline ip2asn TSV/`.gz` database. |
| `-retention-days` | `30` | Purge submissions/events older than N days; `0` disables. |
| `-max-send-targets` | `500` | Max pending recipients per send; `0` disables. |
| `-fail-attempts` | `2` | First N credential submissions get a “wrong password” retry page; `0` redirects immediately. |
| `-cert` | `<data>/tls/cert.pem` | TLS certificate file. |
| `-key` | `<data>/tls/key.pem` | TLS private key file. |
| `-smtp-host` | empty | Seeds a default sending profile. |
| `-smtp-port` | `587` | SMTP port. |
| `-smtp-user` | empty | SMTP username. |
| `-smtp-pass` | empty | SMTP password. |
| `-smtp-tls` | `true` | Use STARTTLS (when false, `tls_mode=none`). |
| `-log-level` | `info` | `debug`, `info`, `warn`, `error`. |
| `-hash-pass` | — | Print a bcrypt hash for the argument and exit. |

## Environment variables

### Core

| Variable | Default | Notes |
| --- | --- | --- |
| `PHISH_LISTEN` | `:8443` | Same as `-listen`. |
| `PHISH_DATA_DIR` | `data` | Same as `-data`. |
| `PHISH_PUBLIC_URL` | derived | Same as `-public-url`. |
| `PHISH_CERT_FILE` / `PHISH_KEY_FILE` | data/tls | TLS files. |
| `PHISH_ADMIN_KEY` | empty | Bearer key. |
| `PHISH_ADMIN_USER` | `admin` | Console username. |
| `PHISH_ADMIN_PASS` | empty | Console password. |
| `PHISH_ADMIN_PASS_HASH` | empty | bcrypt hash (wins over password). |
| `PHISH_SESSION_TTL` | `12` | Session lifetime in hours. |
| `PHISH_TRUSTED_PROXIES` | loopback | Comma-separated CIDRs. |
| `PHISH_CLONE_DENY_PRIVATE` | `false` | SSRF guard for clone/proxy/fetch. |
| `PHISH_SEARCH_URL` | empty | SearXNG base URL for `search_web`. |
| `PHISH_GEOIP_DB` | auto | Offline GeoIP path. |
| `PHISH_RETENTION_DAYS` | `30` | Purge window. |
| `PHISH_MAX_SEND_TARGETS` | `500` | Per-send cap. |
| `PHISH_FAIL_ATTEMPTS` | `2` | Retry prompt count. |
| `PHISH_SECRET_KEY` | generated | 64 hex chars AES-256 key. If empty, `<data>/secret.key` is used/created. |
| `PHISH_DB_DRIVER` | `sqlite` | `sqlite` or `mysql`. |
| `PHISH_DB_DSN` | empty | MySQL DSN, e.g. `phish:pass@tcp(127.0.0.1:3306)/phishsim?charset=utf8mb4&parseTime=true&loc=Local`. |
| `PHISH_MASK_PASSWORDS` | `false` | Mask passwords in the console/CSV (first 2 chars kept). |
| `PHISH_MAX_BODY_BYTES` | `8388608` | Max request body bytes. |
| `PHISH_LOG_FILE` | empty | Also write JSON logs to this file. |

### LLM / console agent

| Variable | Default | Notes |
| --- | --- | --- |
| `PHISH_LLM_BASE_URL` | empty | OpenAI-compatible base URL, e.g. `https://api.deepseek.com/v1`. |
| `PHISH_LLM_KEY` | empty | API key; optional for local servers. |
| `PHISH_LLM_MODEL` | `deepseek-flash` | Default model. |
| `PHISH_LLM_PLAN_MODEL` | empty | Optional planning model for the first agent round. |
| `PHISH_LLM_MODELS` | built-in list | Comma-separated fallback model IDs. |
| `PHISH_LLM_TEMPERATURE` | `0.7` | 0–2. |
| `PHISH_LLM_RATE_PER_MIN` | `30` | Per-session calls/minute; `0` unlimited. |
| `PHISH_AGENT_MAX_ROUNDS` | `24` | Tool rounds per turn, clamped 4–64. |
| `PHISH_AGENT_WORKERS` | `2` | Background job workers, 1–8. |
| `PHISH_AGENT_JOB_RETRIES` | `0` | Retries for a failed background job, 0–5. |
| `PHISH_AGENT_VISION` | enabled | `0` disables screenshot/image input. |
| `PHISH_AGENT_STRICT_HIGH` | `0` | `1` makes high-risk writes confirm even inside an approved task window. |
| `PHISH_FETCH_ALLOWLIST` | empty | Comma-separated domains/subdomains allowed for `fetch_url`/proxy creation. |
| `PHISH_ALERT_WEBHOOK` | empty | POST JSON alerts for send breaker/job failure. |

### Sending / operations

| Variable | Default | Notes |
| --- | --- | --- |
| `PHISH_SMTP_HOST/PORT/USER/PASS/TLS` | — | Seed a default sending profile. |
| `PHISH_SMTP_RATE` | `5` | Outbound emails/second; `0` unlimited. |
| `PHISH_SEND_RETRY` | `2` | Per-recipient retries for transient SMTP errors, 0–5. |
| `PHISH_SEND_BREAKER` | `5` | Consecutive failures before pausing the batch; `0` disables. |
| `PHISH_METRICS_TOKEN` | empty | Required for `/metrics` when set; otherwise loopback only. |
| `PHISH_LOG_FILE` | empty | JSON log tee. |
| `PHISH_TEST_MYSQL_DSN` | — | Test-only DSN for `TestMySQLStore`. |

## Console settings (stored in `app_settings`)

| Setting | Where | Notes |
| --- | --- | --- |
| `public_url` | Settings → Public URL | Overrides `-public-url`; empty falls back. |
| `admin_pass_hash` | Settings → Change password | bcrypt hash; invalidates sessions when changed. |
| `background_version/type` | Settings → Appearance | Uploaded background image metadata. |
| `llm_base_url/model/plan_model/key/temperature` | Settings → Model | Key is AES-GCM sealed at rest. |
| `bounce_imap_*` | Settings → Bounce | IMAP host/port/user/password/TLS/folder; password sealed. |
| `log_retention_days` | Logs page (“retention days”) | 0 = keep forever. |

## Sizing and limits

| Limit | Value |
| --- | --- |
| Chat turns kept | 60 messages / 60k runes |
| HTML handed to the model | 40k runes |
| Single tool result | 12k runes |
| Chat upload | 5 MB; template attachments 5 MB each, 5 per template |
| Payload attachment library | 20 MB per file |
| Inline screenshot | 2 MB |
| Background image | 5 MB |
| Subagents | 4 tasks, 6 rounds each, 3 minutes |
| Background job timeout | 30 minutes |
| Pending confirmation TTL | 15 minutes |
| Content versions kept | 20 per object |

## Example: minimal local run

```bash
./phishsim -listen 127.0.0.1:8443 -data ./data \
  -admin-user admin -admin-pass 'long-random-password' \
  -public-url https://phish.example.com
```

## Example: MySQL + proxy

```bash
PHISH_DB_DRIVER=mysql \
PHISH_DB_DSN='phish:change-me@tcp(127.0.0.1:3306)/phishsim?charset=utf8mb4&parseTime=true&loc=Local' \
./phishsim -listen 127.0.0.1:8443 -data ./data \
  -admin-user admin -admin-pass-hash "$(./phishsim -hash-pass 'long-random-password')" \
  -public-url https://phish.example.com -clone-deny-private
```
