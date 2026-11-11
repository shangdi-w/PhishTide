# Troubleshooting

## I cannot open the admin console

- Use **HTTPS**, not HTTP: `https://127.0.0.1:8443/__admin`.
- The default certificate is self-signed. Accept the warning (Chrome/Edge: Advanced → Proceed; Firefox: Accept the risk).
- If the browser refuses to show a “proceed” option, click the warning page and type `thisisunsafe` in Chrome.
- Do **not** use `https://your-public-host/__admin` if the reverse proxy denies it; that is intentional. Use the SSH tunnel or allow-list the admin IP.
- From another machine, `127.0.0.1` points to that machine. Use the public proxy or an SSH local forward:
  `ssh -N -L 9443:127.0.0.1:8443 user@server`, then `https://127.0.0.1:9443/__admin`.

## Login returns 401 or 429

- 401: wrong username/password, or a stale password. The stored `app_settings.admin_pass_hash` wins over `-admin-pass`; clear it or set a new hash.
- 429: five failures from one IP within 15 minutes trigger a 15-minute lockout. Wait or restart (the limiter is in memory).
- Changing the password invalidates all existing sessions; log in again.

## Email links point to the wrong host

- Check `-public-url` / `PHISH_PUBLIC_URL` and **Settings → Public URL**. The console setting wins.
- Links are generated at send time; already-sent emails keep the old URL.
- Behind a proxy, `-public-url` must be the external address (`https://phish.example.com`), not `127.0.0.1`.

## Nothing is sent

- The campaign must have a **sending profile** with a host; otherwise it is preview-only.
- Check **Dry run** output: template rendering, landing page, recipients, SPF/DKIM/DMARC.
- Check `list_send_failures` / campaign → Send failures for `auth`, `tls`, `dns`, `hard`, `throttle`.
- The circuit breaker pauses after global errors or N consecutive failures; see `stopped_reason`.
- Suppression list and unsubscribed recipients are skipped.
- `-max-send-targets` may reject a large batch; split it or raise the cap.

## Cloned page is blank

- The site is an SPA and its bundle/API was not mirrored. Use **reverse proxy** mode for live SPAs, or re-clone with browser rendering and network capture.
- Static-form mode removes JS; if the login form is rendered by JS it will be missing.
- Run `validate_page` and `preview_page`; check external resources.

## Reverse proxy returns 502

- The upstream is unreachable; proxy pages require the upstream to stay online.
- `-clone-deny-private` blocks private/loopback upstreams.
- Upstream TLS is verified leniently by the proxy, but DNS/connect errors still fail.
- Check the server log for `proxy upstream failed`.

## Screenshots / e2e checks fail

- Chrome/Chromium must be installed on the host running PhishTide.
- On headless servers, install a Chrome that can start without a display, or skip visual/e2e checks.

## MySQL errors on startup

- Check `PHISH_DB_DSN` (user, password, host, port, database, `charset=utf8mb4&parseTime=true`).
- Use a least-privilege user; the database must exist.
- Additive migrations tolerate duplicate columns but not permission errors.

## `/metrics` returns 403

- When `PHISH_METRICS_TOKEN` is set, send `Authorization: Bearer <token>` (or `?token=`).
- When it is not set, only loopback clients are allowed.

## CSV opens with garbled Chinese

- Exports include a UTF-8 BOM; use Excel/WPS “open as UTF-8” if an older tool ignores it.
- Do not re-save the file as ANSI.

## Agent stops early

- Increase `PHISH_AGENT_MAX_ROUNDS` (4–64).
- Break large tasks into smaller ones; use `propose_plan` / `todo_write`.
- Check `read_logs` and `session_metrics` for tool errors or provider errors.
- A tainted session gates writes; confirm in the console, then resume.

## Timezone

- The console displays Asia/Shanghai. Scheduled sends accept RFC3339 with an offset or naive `yyyy-mm-ddThh:mm:ss` interpreted as Beijing time.
