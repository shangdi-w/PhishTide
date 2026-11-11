# 架构

PhishTide 是一个单 Go 二进制 + 内嵌操作员 SPA 的应用。部署时不需要 Node.js，也没有独立的前端构建步骤。

## 进程模型

```
cmd/phishsim/main.go
  ├─ config.FromEnv + 命令行参数
  ├─ store.Open（SQLite）或 store.OpenMySQL（MySQL）
  ├─ 可选离线 GeoIP 载入
  ├─ 日志环形缓冲 + 可选 JSON 日志文件
  ├─ web.Server（全部 HTTP 处理器）
  ├─ 调度协程（到期发送 + 自动收退信）
  ├─ 保留期协程（每日清理）
  ├─ Agent 后台任务 worker
  └─ http.Server（仅 TLS）
```

所有路由共用一个监听端口；落地页和 `/__admin` 同源。需要按路径/来源隐藏后台时，在前面加反向代理。

## 包职责

包按四层组织：**core**（基础设施）、**services**（领域逻辑）、**features**（集成/内容）、**web**（接入层）。

| 包 | 职责 |
| --- | --- |
| `internal/core/config` | 默认值、`PHISH_*` 环境变量、flag、对外地址推导 |
| `internal/core/store` | SQL 建表/迁移、全部持久化方法、SQLite/MySQL 方言 |
| `internal/core/crypto` | AES-256-GCM 与密钥文件 |
| `internal/features/clone` | HTTP/浏览器克隆、资源镜像、HTML/CSS 重写、SPA shim、代理重写、截图、e2e 表单提交 |
| `internal/features/email` | Go 模板渲染、MIME 构造、SMTP 发送、失败分类 |
| `internal/web` | 路由、公共处理器、后台 API、Agent 循环与工具、发送流水线、会话/认证、设置 |
| `internal/services/analyze` | 平台数据快照与文本摘要 |
| `internal/services/report` | 个人/部门风险评分与可打印 HTML |
| `internal/services/hygiene` | 名单体检（格式、重复、职能邮箱、一次性域名、MX） |
| `internal/services/geoip` | 离线 ip2asn IPv4 查询 |
| `internal/services/bounce` | 极简 IMAP 客户端与 RFC 3464 DSN 解析 |
| `internal/services/pdftext` | 无外部依赖的 PDF 文本提取 |
| `internal/services/detect` | User-Agent 分类（人/机器人/沙箱/扫描器） |
| `internal/services/dnscheck` | SPF/DKIM/DMARC 查询 |
| `internal/core/logbuf` | 有界内存 `slog` 缓冲 |
| `internal/core/tlsutil` | 自签证书生成/加载 |

## 请求流程

### 落地页与捕获

```
GET /l/<rid>/            → ResultByRid → GetCampaign → GetPage
                           → IP/链接策略 → 机器人过滤 → 渲染占位符
GET /l/<rid>/assets/...  → page_assets 精确匹配
POST/GET /l/<rid>/submit → 解析 form/json → 字段限长 → RecordSubmission
                           → 可选错误口令重试 → 跳转
```

已终止活动、非人类 UA、跨站请求不计入捕获。配置密钥后，密码与完整字段 JSON 使用 AES-GCM 加密落库。

### 跟踪、举报、退订、行为

- `GET /t/<rid>` 返回 1×1 GIF，记录首次人类打开。
- `GET /r/<rid>` 记录举报；`GET /u/<rid>` 记录退订并加入抑制名单。
- `GET /b/<rid>/<kind>` 记录客户端行为事件（加载、停留、点击、聚焦、提交尝试）。

### 克隆

```
后台克隆 / clone_site
  → clone.CloneWithBrowser（优先）或 clone.Clone（回退）
  → 镜像同源资源 + 浏览器网络捕获
  → 重写引用与表单 action
  → 写入 landing_pages + page_assets
```

### 反向代理

```
GET /l/<rid>/            → 302 /l/<rid>/px/<上游路径>
GET /l/<rid>/px/<path>   → proxyForward
  → 嗅探请求体密码字段
      ├─ 有密码 → RecordSubmission + 本地假应答（绝不转发上游）
      └─ 无密码 → 转发，重写 HTML/CSS/跳转/Cookie
```

### 发送流水线

```
后台发送 / 调度器 / Agent 确认
  → 读取活动 + 模板 + 附件 + 发件账号
  → 计算待发收件人，应用抑制名单与单次上限
  → 逐人渲染 → email.Build → deliver（重试策略）
  → 写 send_ledger + send_failures；全局错误触发熔断
```

### Agent 循环

```
chat/stream（session_id）
  → 读取历史 + 修复残缺 tool-call + 裁剪上下文
  → 系统提示（工具、记忆、任务清单）
  → 每一轮：
       ChatWithTools（流式）
       → 执行工具（只读并行、写操作串行）
       → 写操作门禁 / 待确认
       → 持久化 assistant/tool 轮次
  → 流式返回 delta/工具事件/确认/done
```

### 后台任务

`agent_jobs` 是持久化队列。worker 领取 queued 任务，脱离 HTTP 跑同一循环，失败重试一次，支持 `run_at` 定时，操作员确认后从断点继续。同一会话有锁，交互对话与后台任务不会交错。

## 数据与迁移

- SQLite：单文件 `<data>/phishsim.db`，WAL，单连接。
- MySQL：DDL 在 `internal/core/store/db.go`，增量迁移容忍 duplicate column。
- 每次模板/落地页写入都记录 `content_versions` 快照（每对象最近 20 份）。
- 捕获的敏感字段加密落库；SMTP/LLM/IMAP 凭据加密存放在设置中。

## 并发

- 每会话 Agent 锁（`runMu`）。
- 同一轮内只读工具并发，写操作保持顺序。
- 调度器与退信轮询串行；退信轮询不阻塞调度协程。
- 日志落库用有界 channel，宁可丢弃也不阻塞请求。
- 会话 Cookie 是无状态 HMAC token；改密即更换签名密钥。

## 扩展点

- 在 `internal/web/tools_registry.go` 声明工具，在 `executeTool`（`agent.go`）绑定实现。
- 在 `internal/web/settings.go` 增加设置（读取/保存/JSON）和后台表单。
- 在 `internal/core/store` 增加方法，通过 `s.sql(...)` 同时支持 SQLite/MySQL。
- 在 `serveHTTP`（`server.go`）加公共路由，或在 `adminRoute` 加后台路由。
