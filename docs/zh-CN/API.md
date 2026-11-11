# 后台 API

所有后台路由在 `/__admin` 下，除特别说明外均为 JSON。

## 认证

两种方式：

1. **会话 Cookie** — `POST /__admin/login`，表单字段 `username` + `password`。成功后下发：
   - `phish_admin`（Path `/__admin`，`HttpOnly; Secure; SameSite=Strict`）
   - `phish_admin_p`（Path `/p/`，用于页面预览）
2. **Bearer Key** — `Authorization: Bearer <admin-key>`，需设置 `-admin-key` / `PHISH_ADMIN_KEY`。**不接受查询串 key**。

Cookie 认证的非安全方法（GET/HEAD/OPTIONS 之外）必须同源：服务端检查 `Sec-Fetch-Site`、`Origin` 或 `Referer`。用 Cookie 的 API 客户端要带 `Origin`；Bearer 客户端豁免。

## 错误

| 状态 | 含义 |
| --- | --- |
| 400 | 输入/JSON 无效 |
| 401 | 未认证/凭据无效 |
| 403 | 跨源 Cookie 请求，或无权限 |
| 404 | 路由/对象不存在 |
| 405 | 方法不允许 |
| 429 | 登录限速 |
| 500 | 服务/存储错误 |

错误体：`{"error": "message"}`。

## 公共端点

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/l/<rid>/` | 落地页（代理页 302 到 `/px/`） |
| POST/GET | `/l/<rid>/submit` | 捕获表单提交 |
| GET | `/l/<rid>/assets/<...>` | 克隆资源 |
| ANY | `/l/<rid>/px/<...>` | 反向代理实时转发 |
| GET | `/t/<rid>` | 跟踪像素 |
| GET | `/r/<rid>` / `/u/<rid>` | 举报 / 退订 |
| GET | `/b/<rid>/<kind>` | 行为埋点 |
| GET | `/p/<id>/` | 操作员页面预览（会话或 Bearer） |
| GET | `/p/<id>/assets/<...>` | 预览资源 |
| POST | `/p/<id>/submit` | 预览提交（仅跳转） |
| GET | `/assets/background` | 背景图 |
| GET | `/vendor/<...>` | 内嵌前端资源 |
| GET | `/metrics` | Prometheus 文本（Token 或回环） |

## 控制台 API

### 会话与设置

| 方法 | 路径 |
| --- | --- |
| GET | `/__admin/api/overview` |
| GET | `/__admin/api/settings` |
| POST | `/__admin/api/settings/public-url`（`{public_url}`；空值清除覆盖） |
| POST | `/__admin/api/settings/password`（`{current_password,new_password}`） |
| POST | `/__admin/api/settings/background`（原始图片体；`?reset=1` 清除） |
| GET | `/__admin/api/logs?level=&limit=&offset=` |
| POST | `/__admin/api/logs/retention`（`{days}`） |
| POST | `/__admin/api/logs/clear` |

### 活动

| 方法 | 路径 |
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

### 模板、附件、落地页、版本

| 方法 | 路径 |
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

### 群组与发件账号

| 方法 | 路径 |
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

### LLM 与对话

| 方法 | 路径 |
| --- | --- |
| GET | `/__admin/api/models` |
| GET/POST | `/__admin/api/llm` |
| GET | `/__admin/api/llm/models` |
| GET | `/__admin/api/llm/secret` |
| GET/POST | `/__admin/api/chat/sessions` |
| GET/PATCH/DELETE | `/__admin/api/chat/sessions/<id>` |
| POST | `/__admin/api/chat/stream` |
| POST | `/__admin/api/chat/upload`（multipart `session_id` + `file`） |
| POST | `/__admin/api/chat/confirm` |
| POST | `/__admin/api/chat/action/confirm` |
| GET | `/__admin/api/chat/pending?session_id=` |
| GET/POST | `/__admin/api/agent/jobs` |
| POST | `/__admin/api/agent/jobs/<id>/cancel` |
| POST | `/__admin/api/agent/jobs/<id>/retry` |
| GET | `/__admin/api/agent/metrics?session_id=` |
| GET | `/__admin/api/agent/metrics/global` |

### 搜索、抑制、诊断、维护

| 方法 | 路径 |
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
| POST | `/__admin/api/maintenance/purge`（`{days,confirm}`） |
| GET | `/__admin/api/submissions/export` |
| GET | `/__admin/api/openapi.yaml` |

## SSE 对话流

`POST /__admin/api/chat/stream`，请求 `{session_id, model, message}`（兼容旧格式 `{model, messages}`）。帧格式：

```
data: {"delta":"文本"}
data: {"tool":{"name":"validate_page","status":"start"}}
data: {"tool":{"name":"validate_page","status":"done","ok":true,"note":"..."}}
data: {"action":{...}}          # 待确认的覆盖/计划
data: {"confirm":{...}}         # 待确认的发送
data: {"error":"..."}
data: {"done":true,"usage":{...},"session_id":1}
```

`resume:true` 表示操作员确认后继续，不新增可见用户轮次。

## 示例

```bash
# Bearer 读取概览
curl -sk -H 'Authorization: Bearer <admin-key>' \
  https://127.0.0.1:8443/__admin/api/overview

# 建群组
curl -sk -H 'Authorization: Bearer <admin-key>' -H 'Content-Type: application/json' \
  -d '{"name":"演练 2026","targets":[{"email":"a@example.com","department":"IT"}]}' \
  https://127.0.0.1:8443/__admin/api/groups

# 克隆站点
curl -sk -H 'Authorization: Bearer <admin-key>' -H 'Content-Type: application/json' \
  -d '{"name":"login-clone","url":"https://example.com/login","capture_credentials":true}' \
  https://127.0.0.1:8443/__admin/api/clone

# 设置对外地址
curl -sk -H 'Authorization: Bearer <admin-key>' -H 'Content-Type: application/json' \
  -d '{"public_url":"https://phish.example.com"}' \
  https://127.0.0.1:8443/__admin/api/settings/public-url

# 流式对话
curl -skN -H 'Authorization: Bearer <admin-key>' -H 'Content-Type: application/json' \
  -d '{"session_id":1,"message":"创建一个演练活动"}' \
  https://127.0.0.1:8443/__admin/api/chat/stream
```
