# 安全

## 授权使用

PhishTide 是钓鱼演练工具。只能对你自己拥有或已获得明确书面授权的目标和人员使用。未经同意对第三方使用可能违法；本项目不提供任何担保。

## 威胁模型

| 角色 | 信任级别 | 说明 |
| --- | --- | --- |
| 操作员/管理员 | 可信 | 可访问控制台、配置发信/页面/LLM。 |
| 收件人/访客 | 不可信 | 会打开落地页、提交表单、发送任意请求。 |
| 被克隆站点 | 不可信 | 其 HTML/JS 会被受害者渲染，预览时也会被操作员渲染。 |
| 外部 LLM | 半可信 | 接收提示与工具结果，可能被抓取内容诱导。 |

## 内置防护

- **后台认证**：bcrypt/明文密码或 admin key；HMAC 签名会话 Cookie（`HttpOnly; Secure; SameSite=Strict`）；按 IP 登录锁定（5 次/15 分钟）；改密失效旧会话。
- **CSRF**：Cookie 认证的非安全请求要求同源 `Sec-Fetch-Site`/`Origin`/`Referer`；Bearer 客户端豁免。
- **响应头**：CSP、HSTS、`X-Frame-Options: DENY`、`nosniff`、`no-referrer`、`no-store`。
- **请求限长**：请求体、字段数量/长度、上传大小、表行数上限。
- **SSRF**：`-clone-deny-private`；拒绝跳转到内网地址；链接探测阻断内网；`PHISH_FETCH_ALLOWLIST` 可限制域名。
- **提示注入隔离**：外部内容标记不可信、污染会话、写操作门禁、确认时重放原始参数。
- **密钥处理**：提交密码/字段、payload 附件 AES-256-GCM 加密；SMTP/LLM/IMAP 凭据加密；密钥回读接口记日志；日志脱敏。
- **CSV**：公式注入转义；导出带 UTF-8 BOM。
- **邮件**：拒绝头注入；远程主机拒绝明文 SMTP 凭据；最低 TLS 1.2。
- **预览隔离**：`/p/` 预览加 `sandbox` + `script-src 'none'`，克隆页脚本不能借管理员 Cookie 调后台 API。

## 残留风险

1. **落地页与后台同源**：`/l/...` 与 `/__admin` 同源。管理员登录状态下打开测试链接，克隆页 JS 可携带 Cookie 调后台。`SameSite=Strict` 不阻止同源请求。缓解：演练用独立浏览器配置/虚拟机，或把落地页放到独立域名/端口。
2. **`GET /l/<rid>/submit` 被接受**：兼容 `method=get` 表单，但凭证可能进入 URL、历史、Referer、代理日志。建议生产改 POST-only。
3. **SSRF 是管理员级、默认未收紧**：克隆/代理/fetch 与 LLM Base URL 可访问内网，除非开启 `-clone-deny-private`。建议开启，并在网络层阻断 `169.254.169.254`。
4. **密钥回读接口**：`/llm/secret`、`/profiles/<id>/secret`、`/bounces/secret` 向任意已登录管理员返回明文，虽有日志但无二次认证。需要时可加密码确认或移除。
5. **落盘加密不完整**：提交密码/字段与 payload 附件已加密；用户名、邮箱、主题、发送台账、会话上传、模板附件仍为明文。样本敏感时扩展加密范围。
6. **默认自签 TLS**：浏览器告警，严格客户端可能拒绝。建议反代真证书。
7. **无 MFA、单管理员**：按 IP 锁定挡不住分布式撞库。建议后台仅 VPN/固定 IP 或加 TOTP。
8. **Metrics 查询 Token**：`?token=` 会进代理日志，优先用 `Authorization: Bearer`。
9. **保留期/备份**：捕获凭据敏感。设置保留期、保护备份、演练结束清理数据。

## 加固清单

- [ ] 后台只在回环/VPN/白名单 IP；边缘拒绝 `/__admin`
- [ ] 强密码或 bcrypt；不用 admin key 时关闭
- [ ] 反代真证书 + HSTS
- [ ] 开启 `-clone-deny-private`
- [ ] 导出离开本机时 `PHISH_MASK_PASSWORDS=true`
- [ ] 数据库最小权限、只绑回环
- [ ] `secret.key` 单独备份并保护；备份加密
- [ ] 设置 `-retention-days`，演练后清理
- [ ] LLM 服务商/Base URL 可信；尽量设置 `PHISH_FETCH_ALLOWLIST`
- [ ] 操作员用独立浏览器配置打开测试链接

## 漏洞报告

发现安全问题请在 GitHub 仓库的 Security → Advisories 提交私有报告，不要开公开 issue。请附复现步骤和受影响版本。
