# Security

## Authorized use

PhishTide is a phishing simulation tool. Use it only against people and systems you own or have explicit written authorization to test. Running it against third parties without consent may be illegal. The project ships no warranty.

## Threat model

| Actor | Trust | Notes |
| --- | --- | --- |
| Operator / admin | Trusted | Has console access and can configure sending, pages and the LLM. |
| Recipient / visitor | Untrusted | Sees landing pages, submits forms, can send arbitrary requests. |
| Cloned upstream site | Untrusted | Its HTML/JS is rendered by victims and (in previews) by the operator. |
| External LLM | Semi-trusted | Receives prompts and tool results; may be prompted by fetched content. |

## Built-in controls

- **Console auth** — bcrypt/plaintext password or admin key; HMAC-signed session cookies (`HttpOnly; Secure; SameSite=Strict`); per-IP login lockout (5 failures / 15 min); password change invalidates sessions.
- **CSRF** — cookie-authenticated unsafe requests require same-origin `Sec-Fetch-Site`/`Origin`/`Referer`; Bearer clients are exempt.
- **Headers** — CSP, HSTS, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `no-store` on the console.
- **Request bounds** — max body size, field count/value caps, upload size limits, table row caps.
- **SSRF guards** — `-clone-deny-private` for clone/proxy/fetch; redirects to private addresses refused; link checks block private targets; `PHISH_FETCH_ALLOWLIST` can restrict hosts.
- **Prompt-injection containment** — external content is marked untrusted, taints the session, gates writes, and confirmation replays the original arguments.
- **Secret handling** — passwords/fields and payload attachments are AES-256-GCM sealed at rest; SMTP/LLM/IMAP credentials are encrypted; secret reveal endpoints are logged; logs redact credential-looking values.
- **CSV safety** — formula injection is neutralized; exports include a UTF-8 BOM.
- **Email safety** — header injection is rejected; plaintext SMTP credentials are refused for remote hosts; TLS 1.2 minimum.
- **Preview isolation** — `/p/` previews are sandboxed with `script-src 'none'` so cloned markup cannot call admin APIs with the operator's cookies.

## Residual risks

1. **Same-origin landing pages and console.** `/l/...` and `/__admin` share an origin. If an operator opens a test landing link while logged in, cloned JavaScript can make same-origin requests with the admin cookie. `SameSite=Strict` does not prevent same-site requests. Mitigation: use a separate browser profile/VM for drills, or serve landing pages from a separate host/port.
2. **`GET /l/<rid>/submit` is accepted** for forms that use `method=get`. Credentials can appear in URLs, browser history, Referer and proxy logs. Prefer `method=post`; consider rejecting GET in production.
3. **SSRF is admin-level and opt-in.** Clone/proxy/fetch and the LLM base URL can reach internal services unless `-clone-deny-private` is enabled. Enable it and consider blocking `169.254.169.254` at the network layer.
4. **Secret reveal endpoints** (`/llm/secret`, `/profiles/<id>/secret`, `/bounces/secret`) return plaintext to any authenticated admin session. They are logged but not re-authenticated. Add a password prompt or remove them if your threat model requires it.
5. **At-rest encryption is partial.** Submission passwords/fields and payload attachments are encrypted; usernames, emails, subjects, the send ledger, chat uploads and template attachments are plaintext. Encrypt more if samples are sensitive.
6. **Self-signed TLS by default.** Browsers warn and strict clients may reject it. Use a real certificate on the reverse proxy.
7. **No MFA, single admin.** Per-IP login lockout does not stop distributed guessing. Put the console behind VPN/fixed IP or add TOTP.
8. **Metrics query token.** `?token=` can leak into proxy logs; prefer the `Authorization: Bearer` header.
9. **Retention/backups.** Captured credentials are sensitive. Set a retention window, protect backups, and delete data after the exercise.

## Hardening checklist

- [ ] Console only on loopback / VPN / allow-listed source IP; `/__admin` denied at the edge.
- [ ] Strong admin password or bcrypt hash; admin key disabled if unused.
- [ ] Real TLS certificate; HSTS at the edge.
- [ ] `-clone-deny-private` enabled.
- [ ] `PHISH_MASK_PASSWORDS=true` for exports that leave the host.
- [ ] Least-privilege database account; database bound to loopback.
- [ ] `secret.key` backed up and protected; backups encrypted.
- [ ] `-retention-days` set; data purged after the exercise.
- [ ] LLM provider and base URL trusted; `PHISH_FETCH_ALLOWLIST` set when possible.
- [ ] Operators use a separate browser profile for test links.

## Reporting

If you find a security issue in this project, open a private security advisory on GitHub (Security → Advisories) rather than a public issue. Include reproduction steps and the affected version.
