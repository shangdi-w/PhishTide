# Admin API

All admin routes live under `/__admin`. The console API is JSON unless stated otherwise.

## Authentication

Two methods:

1. **Session cookie** — `POST /__admin/login` with `username` + `password` (form-encoded). On success the server sets:
   - `phish_admin` (Path `/__admin`, `HttpOnly; Secure; SameSite=Strict`)
   - `phish_admin_p` (Path `/p/`, for page previews)
2. **Bearer key** — `Authorization: Bearer <admin-key>` when `-admin-key` / `PHISH_ADMIN_KEY` is set. Query-string keys are **not** accepted.

Cookie-authenticated unsafe methods (anything except GET/HEAD/OPTIONS) must be same-origin: the server checks `Sec-Fetch-Site`, `Origin` or `Referer`. API clients using cookies must send an `Origin`; Bearer clients are exempt.

## Errors

| Status | Meaning |
| --- | --- |
| 400 | Invalid input/JSON |
| 401 | Missing/invalid credentials |
| 403 | Cross-origin cookie request, or forbidden |
| 404 | Unknown route/object |
| 405 | Wrong method |
| 429 | Login rate limit |
| 500 | Server/storage error |

Errors are JSON: `{"error": "message"}`.

## Public endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/l/<rid>/` | landing page (proxy pages redirect to `/px/`) |
| POST/GET | `/l/<rid>/submit` | capture a form submission |
| GET | `/l/<rid>/assets/<...>` | mirrored clone asset |
| ANY | `/l/<rid>/px/<...>` | reverse-proxy live forwarding |
| GET | `/t/<rid>` | tracking pixel |
| GET | `/r/<rid>` / `/u/<rid>` | report / unsubscribe |
| GET | `/b/<rid>/<kind>` | behavior beacon |
| GET | `/p/<id>/` | operator page preview (session or Bearer) |
| GET | `/p/<id>/assets/<...>` | preview asset |
| POST | `/p/<id>/submit` | preview submit (redirect only) |
| GET | `/assets/background` | uploaded/default background |
| GET | `/vendor/<...>` | embedded front-end assets |
| GET | `/metrics` | Prometheus text (token or loopback) |

## Console API

### Session and settings

| Method | Path |
| --- | --- |
| GET | `/__admin/api/overview` |
| GET | `/__admin/api/settings` |
| POST | `/__admin/api/settings/public-url` (`{public_url}`; empty clears) |
| POST | `/__admin/api/settings/password` (`{current_password,new_password}`) |
| POST | `/__admin/api/settings/background` (raw image body; `?reset=1` clears) |
| GET | `/__admin/api/logs?level=&limit=&offset=` |
| POST | `/__admin/api/logs/retention` (`{days}`) |
| POST | `/__admin/api/logs/clear` |

### Campaigns

| Method | Path |
| --- | --- |
| POST | `/__admin/api/campaigns` |
| GET/DELETE | `/__admin/api/campaigns/<id>` |
| POST | `/__admin/api/campaigns/<id>/rename` |
| POST | `/__admin/api/campaigns/<id>/targets` |
| POST | `/__admin/api/campaigns/<id>/submissions/bulk-delete` |
| POST | `/__admin/api/campaigns/<id>/restore` |
| POST | `/__admin/api/campaigns/<id>/purge` |
| POST | `/__admin/api/campaigns/<id>/schedule` |
| GET | `/__admin/api/campaigns/<id>/submissions` |
| GET | `/__admin/api/campaigns/<id>/export` |
| POST | `/__admin/api/campaigns/<id>/send` |
| POST | `/__admin/api/campaigns/<id>/terminate` |
| POST | `/__admin/api/campaigns/<id>/profile` |
| POST | `/__admin/api/campaigns/<id>/landing-page` |
| POST | `/__admin/api/campaigns/<id>/resend` |
| GET | `/__admin/api/campaigns/<id>/events` |
| GET | `/__admin/api/campaigns/<id>/failures` |
| GET | `/__admin/api/campaigns/<id>/bounces` |
| DELETE | `/__admin/api/campaigns/<id>/results/<resultID>` |
| GET | `/__admin/api/campaigns/deleted` |
| GET | `/__admin/api/report?campaign_id=<id>[&format=html]` |

### Templates, attachments, pages, versions

| Method | Path |
| --- | --- |
| GET/POST | `/__admin/api/templates` |
| POST | `/__admin/api/templates/import` |
| DELETE | `/__admin/api/templates/<id>` |
| POST | `/__admin/api/templates/<id>/rename` |
| GET/POST | `/__admin/api/attachments` |
| DELETE | `/__admin/api/attachments/<id>` |
| POST | `/__admin/api/attachments/<id>/attach` |
| GET/POST | `/__admin/api/pages` |
| POST | `/__admin/api/pages/import` |
| DELETE | `/__admin/api/pages/<id>` |
| GET | `/__admin/api/pages/<id>/preview.png` |
| POST | `/__admin/api/pages/<id>/rename` |
| POST | `/__admin/api/pages/<id>/e2e` |
| POST | `/__admin/api/clone` |
| GET | `/__admin/api/versions?kind=&id=&limit=` |
| GET | `/__admin/api/versions/<id>` |
| POST | `/__admin/api/versions/restore` |

### Groups and sending profiles

| Method | Path |
| --- | --- |
| GET/POST | `/__admin/api/groups` |
| DELETE | `/__admin/api/groups/<id>` |
| POST | `/__admin/api/groups/<id>/rename` |
| GET | `/__admin/api/groups/<id>/audit[?mx=0]` |
| GET/POST | `/__admin/api/groups/<id>/targets` |
| DELETE | `/__admin/api/groups/<id>/targets/<targetID>` |
| GET/POST | `/__admin/api/profiles` |
| DELETE | `/__admin/api/profiles/<id>` |
| GET | `/__admin/api/profiles/<id>/secret` |

### LLM and chat

| Method | Path |
| --- | --- |
| GET | `/__admin/api/models` |
| GET/POST | `/__admin/api/llm` |
| GET | `/__admin/api/llm/models` |
| GET | `/__admin/api/llm/secret` |
| GET/POST | `/__admin/api/chat/sessions` |
| GET/PATCH/DELETE | `/__admin/api/chat/sessions/<id>` |
| POST | `/__admin/api/chat/stream` |
| POST | `/__admin/api/chat/upload` (multipart `session_id` + `file`) |
| POST | `/__admin/api/chat/confirm` |
| POST | `/__admin/api/chat/action/confirm` |
| GET | `/__admin/api/chat/pending?session_id=` |
| GET/POST | `/__admin/api/agent/jobs` |
| POST | `/__admin/api/agent/jobs/<id>/cancel` |
| POST | `/__admin/api/agent/jobs/<id>/retry` |
| GET | `/__admin/api/agent/metrics?session_id=` |
| GET | `/__admin/api/agent/metrics/global` |

### Search, suppression, diagnostics, maintenance

| Method | Path |
| --- | --- |
| GET | `/__admin/api/search?q=&limit=` |
| GET/POST | `/__admin/api/suppressions` |
| POST | `/__admin/api/suppressions/bulk` |
| POST | `/__admin/api/suppressions/delete` |
| GET | `/__admin/api/bounces` |
| POST | `/__admin/api/bounces/config` |
| POST | `/__admin/api/bounces/poll` |
| GET | `/__admin/api/bounces/secret` |
| GET | `/__admin/api/analyze` |
| GET | `/__admin/api/send-history?query=&campaign_id=&limit=&offset=` |
| GET | `/__admin/api/dns-check?domain=` |
| GET | `/__admin/api/jobs` |
| POST | `/__admin/api/jobs/<id>/cancel` |
| POST | `/__admin/api/maintenance/purge` (`{days,confirm}`) |
| GET | `/__admin/api/submissions/export` |
| GET | `/__admin/api/openapi.yaml` |

## SSE chat stream

`POST /__admin/api/chat/stream` with `{session_id, model, message}` (or legacy `{model, messages}`). Frames:

```
data: {"delta":"text"}
data: {"tool":{"name":"validate_page","status":"start"}}
data: {"tool":{"name":"validate_page","status":"done","ok":true,"note":"..."}}
data: {"action":{...}}          # pending overwrite/plan confirmation
data: {"confirm":{...}}         # pending send confirmation
data: {"error":"..."}
data: {"done":true,"usage":{...},"session_id":1}
```

`resume:true` continues after an operator confirmation without adding a visible user turn.

## Examples

```bash
# Overview with a Bearer key
curl -sk -H 'Authorization: Bearer <admin-key>' \
  https://127.0.0.1:8443/__admin/api/overview

# Create a group
curl -sk -H 'Authorization: Bearer <admin-key>' -H 'Content-Type: application/json' \
  -d '{"name":"Drill 2026","targets":[{"email":"a@example.com","department":"IT"}]}' \
  https://127.0.0.1:8443/__admin/api/groups

# Clone a site
curl -sk -H 'Authorization: Bearer <admin-key>' -H 'Content-Type: application/json' \
  -d '{"name":"login-clone","url":"https://example.com/login","capture_credentials":true}' \
  https://127.0.0.1:8443/__admin/api/clone

# Set the public URL
curl -sk -H 'Authorization: Bearer <admin-key>' -H 'Content-Type: application/json' \
  -d '{"public_url":"https://phish.example.com"}' \
  https://127.0.0.1:8443/__admin/api/settings/public-url

# Stream an agent turn
curl -skN -H 'Authorization: Bearer <admin-key>' -H 'Content-Type: application/json' \
  -d '{"session_id":1,"message":"创建一个演练活动"}' \
  https://127.0.0.1:8443/__admin/api/chat/stream
```
