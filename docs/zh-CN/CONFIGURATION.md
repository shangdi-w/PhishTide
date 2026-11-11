# 配置

配置分三层，后者覆盖前者：

1. 内置默认值
2. `PHISH_*` 环境变量
3. 命令行 flag（优先级最高）

后台「设置」里改的运行时配置（对外地址、LLM、退信、日志保留、背景）写入 `app_settings` 表，重启后保留。

## 命令行参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-listen` | `:8443` | 监听地址。反代后面用 `127.0.0.1:8443`。 |
| `-data` | `data` | 数据目录：SQLite 库、密钥、TLS 证书、背景图。 |
| `-public-url` | 由 `-listen` 推导 | 生成链接用的对外地址；反代时必须写外部地址。 |
| `-admin-key` | 空 | 后台 API 的 Bearer key；未设密码时兼作登录密码。空则禁用 key 认证。 |
| `-admin-user` | `admin` | 后台用户名。 |
| `-admin-pass` | 空 | 后台明文密码。 |
| `-admin-pass-hash` | 空 | bcrypt 哈希，优先于明文密码。 |
| `-trusted-proxies` | `127.0.0.1/32,::1/128` | 只信任这些 CIDR 的 `X-Forwarded-For`。 |
| `-clone-deny-private` | `false` | 拒绝克隆/代理解析到内网、回环、链路本地的地址。 |
| `-geoip-db` | 自动探测数据目录 | 离线 ip2asn TSV/`.gz` 库。 |
| `-retention-days` | `30` | 清理 N 天前的提交/事件；`0` 关闭。 |
| `-max-send-targets` | `500` | 单次发送上限；`0` 关闭。 |
| `-fail-attempts` | `2` | 前 N 次提交返回“密码错误”重试页；`0` 直接跳转。 |
| `-cert` | `<data>/tls/cert.pem` | TLS 证书。 |
| `-key` | `<data>/tls/key.pem` | TLS 私钥。 |
| `-smtp-host` | 空 | 种一个默认发件账号。 |
| `-smtp-port` | `587` | SMTP 端口。 |
| `-smtp-user` / `-smtp-pass` | 空 | SMTP 账号/密码。 |
| `-smtp-tls` | `true` | 使用 STARTTLS（false 则 `tls_mode=none`）。 |
| `-log-level` | `info` | `debug` / `info` / `warn` / `error`。 |
| `-hash-pass` | — | 打印参数的 bcrypt 哈希后退出。 |

## 环境变量

### 核心

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PHISH_LISTEN` | `:8443` | 同 `-listen`。 |
| `PHISH_DATA_DIR` | `data` | 同 `-data`。 |
| `PHISH_PUBLIC_URL` | 推导值 | 同 `-public-url`。 |
| `PHISH_CERT_FILE` / `PHISH_KEY_FILE` | data/tls | TLS 文件。 |
| `PHISH_ADMIN_KEY` | 空 | Bearer key。 |
| `PHISH_ADMIN_USER` | `admin` | 用户名。 |
| `PHISH_ADMIN_PASS` | 空 | 密码。 |
| `PHISH_ADMIN_PASS_HASH` | 空 | bcrypt 哈希（优先）。 |
| `PHISH_SESSION_TTL` | `12` | 会话有效期（小时）。 |
| `PHISH_TRUSTED_PROXIES` | 回环 | 逗号分隔 CIDR。 |
| `PHISH_CLONE_DENY_PRIVATE` | `false` | 克隆/代理/fetch 的 SSRF 防护。 |
| `PHISH_SEARCH_URL` | 空 | `search_web` 用的 SearXNG 地址。 |
| `PHISH_GEOIP_DB` | 自动 | 离线 GeoIP 路径。 |
| `PHISH_RETENTION_DAYS` | `30` | 保留天数。 |
| `PHISH_MAX_SEND_TARGETS` | `500` | 单次发送上限。 |
| `PHISH_FAIL_ATTEMPTS` | `2` | 错误口令重试次数。 |
| `PHISH_SECRET_KEY` | 自动生成 | 64 位 hex AES-256 密钥；空则用 `<data>/secret.key`。 |
| `PHISH_DB_DRIVER` | `sqlite` | `sqlite` 或 `mysql`。 |
| `PHISH_DB_DSN` | 空 | MySQL DSN，例如 `phish:pass@tcp(127.0.0.1:3306)/phishsim?charset=utf8mb4&parseTime=true&loc=Local`。 |
| `PHISH_MASK_PASSWORDS` | `false` | 后台/CSV 只显示密码前两位。 |
| `PHISH_MAX_BODY_BYTES` | `8388608` | 请求体上限。 |
| `PHISH_LOG_FILE` | 空 | 同时写 JSON 日志文件。 |

### LLM / 控制台 Agent

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PHISH_LLM_BASE_URL` | 空 | OpenAI 兼容 Base URL，如 `https://api.deepseek.com/v1`。 |
| `PHISH_LLM_KEY` | 空 | API Key；本地服务可空。 |
| `PHISH_LLM_MODEL` | `deepseek-flash` | 默认模型。 |
| `PHISH_LLM_PLAN_MODEL` | 空 | 首轮规划模型（可选）。 |
| `PHISH_LLM_MODELS` | 内置列表 | 逗号分隔的候选模型。 |
| `PHISH_LLM_TEMPERATURE` | `0.7` | 0–2。 |
| `PHISH_LLM_RATE_PER_MIN` | `30` | 每会话每分钟调用上限；`0` 不限。 |
| `PHISH_AGENT_MAX_ROUNDS` | `24` | 单轮工具往返，4–64。 |
| `PHISH_AGENT_WORKERS` | `2` | 后台任务 worker，1–8。 |
| `PHISH_AGENT_JOB_RETRIES` | `0` | 后台任务失败重试，0–5。 |
| `PHISH_AGENT_VISION` | 开 | `0` 关闭截图/图片输入。 |
| `PHISH_AGENT_STRICT_HIGH` | `0` | `1` 让高危写操作在审批窗口内也要确认。 |
| `PHISH_FETCH_ALLOWLIST` | 空 | 允许 `fetch_url`/建代理页的域名白名单。 |
| `PHISH_ALERT_WEBHOOK` | 空 | 发送熔断/任务失败时 POST JSON 告警。 |

### 发送与运维

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PHISH_SMTP_HOST/PORT/USER/PASS/TLS` | — | 种默认发件账号。 |
| `PHISH_SMTP_RATE` | `5` | 每秒发信数；`0` 不限。 |
| `PHISH_SEND_RETRY` | `2` | 临时 SMTP 错误重试，0–5。 |
| `PHISH_SEND_BREAKER` | `5` | 连续失败多少个收件人暂停本批；`0` 关闭。 |
| `PHISH_METRICS_TOKEN` | 空 | 设置后 `/metrics` 需要 Token，否则仅回环可访问。 |
| `PHISH_LOG_FILE` | 空 | JSON 日志外送。 |
| `PHISH_TEST_MYSQL_DSN` | — | 仅测试用。 |

## 后台设置（`app_settings`）

| 设置 | 位置 | 说明 |
| --- | --- | --- |
| `public_url` | 设置 → 对外地址 | 覆盖 `-public-url`；清空回退。 |
| `admin_pass_hash` | 设置 → 修改密码 | 改密后旧会话失效。 |
| `background_version/type` | 设置 → 外观 | 背景图元数据。 |
| `llm_*` | 设置 → 模型 | Key 加密存储。 |
| `bounce_imap_*` | 设置 → 退信 | 密码加密存储。 |
| `log_retention_days` | 设置 → 数据维护 | 0 = 永久保留。 |

## 限额

| 限额 | 值 |
| --- | --- |
| 上下文保留 | 60 条消息 / 6 万字符 |
| 交给模型的 HTML | 4 万字符 |
| 单个工具结果 | 1.2 万字符 |
| 会话上传 | 5 MB；模板附件 5 MB/个、每模板 5 个 |
| 附件库 | 单文件 20 MB |
| 内联截图 | 2 MB |
| 背景图 | 5 MB |
| 子代理 | 4 个任务，每个 6 轮、3 分钟 |
| 后台任务超时 | 30 分钟 |
| 待确认 TTL | 15 分钟 |
| 版本快照 | 每对象 20 份 |
