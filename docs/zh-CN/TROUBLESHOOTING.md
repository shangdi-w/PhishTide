# 排障

## 打不开后台

- 必须用 **HTTPS**：`https://127.0.0.1:8443/__admin`。
- 默认自签证书，浏览器会警告。Chrome/Edge 点「高级 → 继续前往」；Firefox 点「接受风险并继续」。
- Chrome 没有继续按钮时，在警告页点一下，键盘输入 `thisisunsafe`。
- 不要用 `https://公网地址/__admin`（反代通常会返回 404，这是故意的）；走 SSH 隧道或把管理 IP 加入白名单。
- 在另一台机器上，`127.0.0.1` 指向那台机器。用公网代理或 SSH 本地转发：
  `ssh -N -L 9443:127.0.0.1:8443 user@server`，然后打开 `https://127.0.0.1:9443/__admin`。

## 登录 401 / 429

- 401：用户名/密码错误，或密码已变更。`app_settings.admin_pass_hash` 优先于 `-admin-pass`；清空它或写入新哈希。
- 429：同一 IP 15 分钟内失败 5 次，锁定 15 分钟。等待或重启进程（限速在内存中）。
- 改密会让所有旧会话失效，需要重新登录。

## 邮件链接主机不对

- 检查 `-public-url` / `PHISH_PUBLIC_URL` 和后台「设置 → 对外地址」。后台设置优先。
- 链接在发送时生成；已发出的邮件不会改。
- 反代后面 `-public-url` 必须是外部地址（`https://phish.example.com`），不能是 `127.0.0.1`。

## 发不出去

- 活动必须绑定**发件账号**（有 host），否则只能预览。
- 看**干跑**输出：模板渲染、落地页、收件人、SPF/DKIM/DMARC。
- 看 `list_send_failures` / 活动详情「发送失败」：`auth`、`tls`、`dns`、`hard`、`throttle`。
- 全局错误或连续失败会触发熔断，响应里有 `stopped_reason`。
- 抑制名单和已退订收件人会被跳过。
- `-max-send-targets` 可能拒绝大批量；拆批或调高上限。

## 克隆页空白

- 站点是 SPA，bundle/API 没镜像到。用**反向代理**模式，或重新用浏览器渲染 + 网络捕获克隆。
- 静态表单模式会去掉 JS；由 JS 渲染的登录框会消失。
- 跑 `validate_page` 和 `preview_page`，检查外部资源。

## 反向代理 502

- 上游不可达；代理页要求上游在线。
- `-clone-deny-private` 会拒绝内网/回环上游。
- 代理对上游 TLS 宽松，但 DNS/连接错误仍会失败。
- 看服务日志 `proxy upstream failed`。

## 截图 / 端到端自检失败

- 运行 PhishTide 的主机必须安装 Chrome/Chromium。
- 无显示服务器的环境要装可无头启动的 Chrome，或跳过视觉/端到端检查。

## MySQL 启动报错

- 检查 `PHISH_DB_DSN`（用户、密码、主机、端口、库名、`charset=utf8mb4&parseTime=true`）。
- 用最小权限账号；数据库要提前创建。
- 增量迁移容忍重复列，但不容忍权限错误。

## `/metrics` 返回 403

- 设置 `PHISH_METRICS_TOKEN` 后要带 `Authorization: Bearer <token>`（或 `?token=`）。
- 未设置时只允许回环访问。

## CSV 中文乱码

- 导出带 UTF-8 BOM；老工具忽略 BOM 时用 Excel/WPS 的“UTF-8 打开”。
- 不要把文件另存为 ANSI。

## Agent 提前停止

- 调大 `PHISH_AGENT_MAX_ROUNDS`（4–64）。
- 把大任务拆小；用 `propose_plan` / `todo_write`。
- 看 `read_logs`、`session_metrics` 里的工具/服务商错误。
- 污点会话会门禁写操作；在控制台确认后继续。

## 时区

- 控制台按 Asia/Shanghai 显示。定时发送接受带偏移的 RFC3339，或按北京时间解释的 `yyyy-mm-ddThh:mm:ss`。
