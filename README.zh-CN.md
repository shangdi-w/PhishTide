<p align="center">
  <strong>遇到问题？扫码联系作者</strong><br>
  <img src="docs/images/wechat-contact.jpg" width="220" alt="微信二维码">
</p>

# PhishTide — 钓鱼演练平台（中文手册）

[English](README.md) | 简体中文

用于**已授权的钓鱼演练与内部员工安全意识培训**的自托管平台，覆盖完整链路：邮件生成 → 落地页 → 跟踪 → 凭证/表单捕获 → 风险报告与 CSV 导出。

> **仅限授权使用。** 请只在自有系统，或已获得明确书面授权的范围内使用。作者不提供任何担保，也不对滥用负责。见 [SECURITY.md](SECURITY.md)。
>
> **只读仓库：** 访客可以查看、克隆和下载；只有作者可以推送，不接受访客提交的 PR。

**文档：** [Docker 一键启动](docs/zh-CN/DOCKER.md) · [一键部署](docs/zh-CN/ONE-CLICK.md) · [后台功能图解](docs/zh-CN/UI-GUIDE.md) · [配置](docs/zh-CN/CONFIGURATION.md) · [部署](docs/zh-CN/DEPLOYMENT.md) · [控制台 Agent](docs/zh-CN/AGENT.md) · [后台 API](docs/zh-CN/API.md) · [排障](docs/zh-CN/TROUBLESHOOTING.md)

## 快速开始

### 方式 A — Docker（推荐）

内置 Chromium 和中文字体，Linux / macOS / Windows（Docker Desktop）通用：

```bash
git clone https://github.com/shangdi-w/PhishTide.git && cd PhishTide
./deploy/docker/quickstart.sh      # 或 --binary ./phishsim-linux-amd64
```

脚本会生成随机后台密码、构建镜像并启动容器，数据存在 Docker 卷里。镜像源、备份、升级与排障：[docs/zh-CN/DOCKER.md](docs/zh-CN/DOCKER.md)。

### 方式 B — Ubuntu/Debian 一键包

1. 从 [Releases](https://github.com/shangdi-w/PhishTide/releases) 下载 `phishsim-oneclick-linux-amd64.tar.gz`（ARM64 用 arm64 包）。
2. 解压：`tar xzf phishsim-oneclick-linux-amd64.tar.gz && cd phishsim-oneclick-linux-amd64`
3. 安装：`sudo ./install.sh`

安装脚本会创建 systemd 服务、默认使用 SQLite、生成后台密码、放行防火墙端口，并打印后台地址。小白教程：[docs/zh-CN/ONE-CLICK.md](docs/zh-CN/ONE-CLICK.md)。一键包说明：[deploy/oneclick/README.md](deploy/oneclick/README.md)。

> **最省事的方法：** 把服务器 SSH 账号密码和本仓库地址交给一个能执行命令的 AI（Cursor、Codex 等），让它按一键包装完。提示词模板和安全注意事项：[docs/zh-CN/ONE-CLICK.md 第 17 节](docs/zh-CN/ONE-CLICK.md#17-让-ai-帮你部署最省事)。

### 方式 C — 源码编译

```bash
git clone https://github.com/shangdi-w/PhishTide.git && cd PhishTide
go build -o phishsim ./cmd/phishsim   # Windows 下产物为 phishsim.exe

./phishsim \
  -listen :8443 \
  -data ./data \
  -admin-user admin \
  -admin-pass '换成长随机密码' \
  -public-url https://phish.example.com
```

打开 `https://host:8443/__admin`，未登录会跳转到 `/__admin/login`。监听端只提供 TLS：首次启动自动生成自签证书（请加入信任库，或在 nginx/Caddy 终结 TLS 并换真实证书）。需要 Go **1.27+**；克隆、截图和端到端自检需要操作员主机装有 Chrome/Chromium。

## 它做什么

```
目标名单 ──► 活动 ──► 邮件模板 ──► SMTP ──► 收件人邮箱
                                               │
                     跟踪像素（/t/）与链接（/l/）│
                                               ▼
                                  落地页（模板 / 克隆 / 反向代理）
                                               │
                                  表单提交（/l/<token>/submit）
                                               ▼
                                  捕获字段 ──► 后台 · CSV · 风险报告
```

## 功能

**内容生成**

- 钓鱼邮件：内置模板 + Go 模板变量，按目标逐人渲染，含跟踪链接、跟踪像素、纯文本回退与客户端兼容元标签。
- 钓鱼网站：内置登录页模板；克隆真实站点（无头浏览器渲染、同源资源镜像、SPA 的 XHR/fetch 本地重放）；静态表单模式；以及**反向代理模式**——实时转发上游站点，密码提交只记录在本地、绝不转发给真实站点。

**发送与策略**

- A/B 双模板按比例分流，报告分变体统计。
- 活动级链接有效期、提交后即失效的一次性链接、IP/CIDR 允许/拒绝名单、种子投递。
- 抑制名单、逐收件人失败分类 + 重试 + 熔断、IMAP DSN 退信恢复，以及活动删除后仍保留的发送台账。

**捕获与报告**

- 捕获账号、密码和**所有提交的表单字段**；静态加密（AES-256-GCM）；CSV 导出带 UTF-8 BOM，并对公式注入做中和。
- 按个人与部门生成风险评分报告，可打印 HTML。

**平台能力**

- 后台控制台：活动、目标组、模板、落地页、附件、提交记录、日志、全局搜索与设置。
- 可选 OpenAI 兼容的**控制台 AI Agent**：57 个工具、确认门禁、后台任务、只读子代理、任务清单与长期记忆。
- 默认 SQLite，可选 MySQL 8；离线 GeoIP；名单体检（MX/职能邮箱/一次性邮箱）；SPF/DKIM/DMARC 预检。
- Prometheus `/metrics`、JSON 日志外送、每次推送自动跑 CI。

**安全**

- bcrypt/明文/admin-key 三种登录方式，HMAC 签名的 `HttpOnly; Secure; SameSite=Strict` 会话，按 IP 锁定，改密码即让旧会话失效。
- CSRF 防护、只信任受信代理的 `X-Forwarded-For`、CSP/HSTS/frame/nosniff/no-referrer、请求体/字段/上传大小上限。
- 可选 SSRF 防护（`-clone-deny-private`）、提示注入遏制、`/p/` 预览沙箱。

## 后台

控制台是内嵌在 `/__admin` 的单页应用。逐屏说明、每项设置与 AI 一键发送实测：[docs/zh-CN/UI-GUIDE.md](docs/zh-CN/UI-GUIDE.md)。

### 登录口令

三选一：

```bash
-admin-pass '明文密码'          # 或 PHISH_ADMIN_PASS
-admin-pass-hash '<bcrypt哈希>' # 或 PHISH_ADMIN_PASS_HASH，优先级最高
-admin-key '<随机串>'           # 未设密码时，管理密钥兼作登录密码
```

生成 bcrypt 哈希：`./phishsim -hash-pass '你的密码'`（Windows 为 `./phishsim.exe`）。登录成功后下发签名会话 Cookie；同一 IP 15 分钟内失败 5 次锁定 15 分钟；改密码会立即让所有旧会话失效。

### 运行时设置

后台「设置 → 对外地址」可改**对外地址**（`public_url`）：邮件里的落地页、跟踪像素、举报/退订链接，以及后台「复制链接」都使用它。留空则回退到 `-public-url` / `PHISH_PUBLIC_URL`；修改立即生效，换服务器或公网 IP 时不必重启。它只改链接，TLS 证书和 nginx 的域名/端口要同步更新。

## 架构

```
cmd/phishsim/main.go            入口：配置、数据库、TLS、HTTP server
internal/core/                  配置、加密、日志、TLS、数据层
internal/services/              分析、报告、名单体检、GeoIP、退信/DSN、PDF、检测、DNS 检查
internal/features/              站点克隆、邮件渲染/SMTP、LLM 客户端
internal/web/                   公共入口（/l/、/t/、/submit）+ /__admin API
internal/web/static/admin.html  操作员后台单页
```

按职责分为四层：

- **core** — 基础设施：配置、加密、持久化、日志、TLS。
- **services** — 领域逻辑：分析、报告、名单体检、GeoIP、退信、PDF、检测、DNS。
- **features** — 集成/内容：站点克隆、邮件、LLM。
- **web** — 接入层：路由、公共门户、后台 API、控制台 Agent、内嵌 SPA。

## 数据模型（SQLite / MySQL）

| 表 | 用途 |
| --- | --- |
| `campaigns` | 活动（绑定邮件模板 + 落地页；可选 B 模板与分流比例、链接有效期/一次性、IP 名单、种子邮箱） |
| `targets` | 目标（每人一个 `token`，含 sent/opened/clicked/submitted 状态；`department`/`position` 用于部门聚合与风险报告） |
| `email_templates` | 邮件模板（subject/html/text） |
| `landing_pages` + `page_assets` | 落地页（模板或克隆 + 镜像资源） |
| `events` | 跟踪事件（opened/clicked/submitted） |
| `submissions` | 捕获的完整表单（username/password + 全部字段 JSON） |
| `send_ledger` | 发送台账（活动删除后仍保留，含 Message-ID 与失败分类） |
| `bounces` / `send_failures` | 退信（DSN）与逐收件人发送失败诊断 |
| `suppressions` | 跨活动抑制名单（硬退/退订/手动/投诉） |
| `content_versions` | 邮件模板与落地页的历史版本（每对象保留最近 20 份） |

## 配置

三层叠加：内置默认 → `PHISH_*` 环境变量 → 命令行 flag（优先级最高）。后台保存的设置（对外地址、模型、退信邮箱、日志保留、背景图）存在 `app_settings`，重启不丢。

常用项：

| Flag / 变量 | 默认 | 作用 |
| --- | --- | --- |
| `-listen` / `PHISH_LISTEN` | `:8443` | 监听地址；反代后面用 `127.0.0.1:8443`。 |
| `-data` / `PHISH_DATA_DIR` | `data` | SQLite、密钥、TLS 证书、背景图目录。 |
| `-public-url` / `PHISH_PUBLIC_URL` | 自动推导 | 生成链接用的对外地址。 |
| `-admin-user` / `-admin-pass` / `-admin-key` | `admin` / 空 / 空 | 后台凭证。 |
| `-trusted-proxies` | 回环 | 只有这些 CIDR 的 `X-Forwarded-For` 被采信。 |
| `-clone-deny-private` | `false` | 拒绝克隆/代理解析到内网、回环地址的 URL。 |
| `-retention-days` | `30` | 自动清理 N 天前的提交与事件；`0` 关闭。 |
| `-max-send-targets` | `500` | 单次发送待发人数上限；`0` 关闭。 |
| `-fail-attempts` | `2` | 第 N 次密码提交前返回“密码错误”；`0` 立即跳转。 |
| `PHISH_MASK_PASSWORDS` | `false` | 后台与 CSV 只显示密码前两位。 |
| `PHISH_DB_DRIVER` / `PHISH_DB_DSN` | `sqlite` / 空 | 改为 `mysql` 即切换 MySQL 8。 |
| `PHISH_SECRET_KEY` | 自动生成 | 64 位十六进制 AES-256 密钥；否则用 `<data>/secret.key`。 |

完整说明——全部 flag、环境变量、限额与后台设置：[docs/zh-CN/CONFIGURATION.md](docs/zh-CN/CONFIGURATION.md)。SMTP 可选：未配置时仍可生成和预览邮件。

### 邮件模板变量

`{{.FirstName}}` `{{.LastName}}` `{{.Email}}` `{{.Position}}` `{{.TrackingURL}}` `{{.TrackingPixel}}` `{{.FromName}}` `{{.FromEmail}}`

### 跟踪 URL 结构

| 路径 | 作用 |
| --- | --- |
| `/l/<token>/` | 落地页（首次访问记为 clicked）；反向代理页 302 到 `/l/<token>/px/<上游路径>` |
| `/l/<token>/submit` | 表单提交 → 捕获凭证与全部字段 |
| `/l/<token>/assets/<...>` | 克隆页镜像资源 |
| `/l/<token>/px/<上游路径>` | 反向代理页实时转发（重写同源引用、Script 内请求与 Cookie 作用域） |
| `/t/<token>` | 邮件跟踪像素（记为 opened） |
| `/r/<token>` / `/u/<token>` | 举报 / 退订 |

命中 IP 拒绝名单（或未命中非空允许名单）返回 403；链接过期或已被一次性消耗返回 410。

## 克隆与反向代理

| 模式 | 做法 | 适用 | 代价 |
| --- | --- | --- | --- |
| 克隆（默认） | 无头浏览器渲染 → 保存 HTML 快照 + 镜像同源资源；同时记录浏览器网络，把懒加载分块与 XHR/fetch JSON 一并镜像，SPA shim 用它们本地应答页面脚本的请求 | 大多数站点；演练期间上游离线也能用 | 页面不是逐帧还原，个别强依赖实时接口的交互会退化 |
| 克隆（静态表单模式） | 去 JS，只留 HTML/CSS，表单提交回平台 | 静态登录页、SSR 页面 | JS 动态渲染出的登录框会消失 |
| 反向代理 | 不存快照，实时转发上游；重写同源引用、脚本内请求、Cookie 作用域与跳转 | 复杂 SPA、SSO、完整登录流程 | 演练期间上游必须在线；平台成为流量的中间人 |

请求体里命中 `password/passwd/pass/pwd/密码` 的提交一律**不转发上游**，由平台记录后本地返回成功应答（连续失败达 `-fail-attempts` 后返回 401），所以演练不会真的登录目标系统。凭证提取规则：`username/user/email/login/account/name` 首个非空值为账号，`password/pass/pwd/passwd` 首个非空值为密码，其余字段原样保留。

已知限制：代理不转发 WebSocket 升级与 service worker；页面若用 `location=` 硬跳转到绝对路径，会跳出代理前缀；只改写文本类响应（单响应上限 32MB）；需要登录态才能看到的页面，克隆只能拿到匿名可见的部分。

## AI 对话 / 控制台 Agent（可选）

「AI 对话」页填写 OpenAI 兼容端点（Base URL / API Key / 模型），也可用环境变量启动：

```bash
PHISH_LLM_BASE_URL=https://api.deepseek.com/v1 \
PHISH_LLM_KEY=your-key PHISH_LLM_MODEL=deepseek-chat ./phishsim.exe ...
```

配置好后，可以直接让 AI 生成邮件/落地页、创建或修改发件账号、建活动、干跑、发送（两段式确认）、查发送失败/退信/风险报告。真实 AI 一键发送实测截图见 [docs/zh-CN/UI-GUIDE.md 第 21 节](docs/zh-CN/UI-GUIDE.md#21-ai-一键发送实战)。

要点：

- **57 个工具**：目标组、模板、附件、落地页、克隆/代理、自检、截图、版本历史、发件账号、活动、干跑、风险报告、发送台账/状态、退信、抑制名单、全局检索、GeoIP、任务清单、计划、运维诊断、后台任务、子代理、长期记忆。
- **自检闭环**：`validate_page`、`preview_page`、`dry_run_campaign`、`e2e_check_page` 在发送前把关。
- **写操作门禁**：覆盖、高危写、污点会话与多步计划都要操作员确认；确认后按模型**原始参数**重放。
- **两段式发送**：`send_campaign` 只准备，操作员点「确认发送」才真正发信。
- **后台任务/子代理/清单/记忆**：任务脱离浏览器、重启后继续；最多 4 个只读子代理；会话级清单；跨会话记忆。

完整说明：[docs/zh-CN/AGENT.md](docs/zh-CN/AGENT.md)。

## 后台 API

需要登录会话 Cookie，或 `Authorization: Bearer <admin-key>`（拒绝 query 传 key）。完整端点、SSE 帧与 curl 示例见 [docs/zh-CN/API.md](docs/zh-CN/API.md)。运行后经「设置 → API 文档」或 `GET /__admin/api/openapi.yaml` 查看 OpenAPI。

## 部署

单机二进制/SQLite、MySQL、TLS、nginx/Caddy、SSH 隧道、systemd、备份与升级：[docs/zh-CN/DEPLOYMENT.md](docs/zh-CN/DEPLOYMENT.md)。把 `/__admin` 挡在公网之外（反代拒绝、VPN 或 SSH 隧道）；克隆/代理 URL 不完全可信时开启 `-clone-deny-private`；数据库账号最小权限，使用真实证书。

落地页和后台同源：**不要在登录后台的浏览器里打开演练链接**，用独立浏览器配置或独立主机。

## 开发

```bash
go vet ./...
go test ./...
go build ./...
```

测试离线且确定（LLM 调用为桩）。`scripts/clone_probe` 是开发期探针，用于查看一次克隆抓到了哪些资源与接口。见 [CONTRIBUTING.md](CONTRIBUTING.md) 与 [docs/zh-CN/BUILD.md](docs/zh-CN/BUILD.md)。

### 预编译二进制

GitHub Releases 提供带平台标注的静态二进制（CGO 关闭，不依赖 glibc）：

| 文件 | 平台 |
| --- | --- |
| `phishsim-linux-amd64` | Ubuntu 20.04+/Debian 11+ x86_64 |
| `phishsim-linux-arm64` | Ubuntu 22.04+ ARM64（Graviton/Ampere） |
| `phishsim-windows-amd64.exe` | Windows 10/11 x64 |
| `phishsim-oneclick-linux-amd64.tar.gz` | Ubuntu/Debian x86_64 一键部署包 |
| `phishsim-oneclick-linux-arm64.tar.gz` | Ubuntu/Debian ARM64 一键部署包 |
| `SHA256SUMS` | 全部资产的校验和 |

重新构建：`./scripts/build-release.sh 0.1.0`；校验：`sha256sum -c SHA256SUMS`。

## 文档索引

| 中文 | English |
| --- | --- |
| [文档索引](docs/README.md) | [Docs index](docs/README.md) |
| [Docker](docs/zh-CN/DOCKER.md) | [Docker](docs/en/DOCKER.md) |
| [一键部署](docs/zh-CN/ONE-CLICK.md) | [One-click deployment](docs/en/ONE-CLICK.md) |
| [配置](docs/zh-CN/CONFIGURATION.md) | [Configuration](docs/en/CONFIGURATION.md) |
| [部署](docs/zh-CN/DEPLOYMENT.md) | [Deployment](docs/en/DEPLOYMENT.md) |
| [编译](docs/zh-CN/BUILD.md) | [Build](docs/en/BUILD.md) |
| [架构](docs/zh-CN/ARCHITECTURE.md) | [Architecture](docs/en/ARCHITECTURE.md) |
| [控制台 Agent](docs/zh-CN/AGENT.md) | [Console agent](docs/en/AGENT.md) |
| [API](docs/zh-CN/API.md) | [API](docs/en/API.md) |
| [安全](docs/zh-CN/SECURITY.md) | [Security](docs/en/SECURITY.md) |
| [排障](docs/zh-CN/TROUBLESHOOTING.md) | [Troubleshooting](docs/en/TROUBLESHOOTING.md) |
| [后台功能图解](docs/zh-CN/UI-GUIDE.md) | — |

## 目录结构

```
cmd/phishsim/         入口
internal/
  core/               配置、加密、日志、TLS、数据层
  services/           分析、报告、名单体检、GeoIP、退信、PDF、检测、DNS
  features/           克隆、邮件、LLM
  web/                HTTP/公共门户/后台 API/Agent + 内嵌控制台
deploy/               通用部署模板（Caddy、frp、备份、env 示例）
docs/                 中英文手册
scripts/              clone_probe、fetch_geoip.sh、build-release.sh
```

## License

未授予开源许可。源码仅用于查看与下载，版权归作者所有。`internal/web/static/vendor/` 下的第三方前端资源（Vue、Element Plus）保留各自许可证。
