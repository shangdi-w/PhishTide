# 控制台 AI Agent

控制台助手是一个 OpenAI 兼容的函数调用 Agent，可选；不配置 LLM 平台照常工作。它能直接操作平台，而不是只回文字。

## 配置

设置 → 模型，或环境变量：

```bash
PHISH_LLM_BASE_URL=https://api.deepseek.com/v1
PHISH_LLM_KEY=your-key
PHISH_LLM_MODEL=deepseek-chat
# 可选：
PHISH_LLM_PLAN_MODEL=deepseek-reasoner
PHISH_LLM_TEMPERATURE=0.7
PHISH_LLM_RATE_PER_MIN=30
```

任何 OpenAI 兼容端点都可以（DeepSeek、OpenAI、Moonshot、本地 vLLM/Ollama）。本地服务 Key 可留空。

## 工具（57 个）

按用途分组，名称稳定；注册表在 `internal/web/tools_registry.go`。

### 目标与名单

`list_groups`、`create_group`、`import_csv_to_group`、`audit_group`

### 邮件模板与附件

`list_templates`、`get_template`、`create_email_template`、`update_email_template`、`add_template_attachments`、`list_attachments`、`attach_attachment_to_template`

### 落地页与克隆

`list_pages`、`get_page`、`fetch_url`、`search_web`、`clone_site`、`create_landing_page`、`create_proxy_page`、`update_landing_page`、`patch_page`、`validate_page`、`preview_page`、`e2e_check_page`、`list_versions`、`restore_version`

### 发件账号与活动

`list_sending_profiles`、`test_send`、`create_sending_profile`、`create_campaign`、`add_campaign_targets`、`list_campaigns`、`dry_run_campaign`、`risk_report`、`send_campaign`、`list_send_failures`

### 发送事实与历史

`send_history`、`send_status`、`search_chat_history`、`list_bounces`、`poll_bounces`

### 抑制与检索

`list_suppressions`、`add_suppression`、`remove_suppression`、`global_search`

### 诊断

`get_health`、`read_logs`、`db_stats`、`geo_lookup`、`session_metrics`

### 编排

`propose_plan`、`todo_write`、`todo_list`、`dispatch_subagents`、`start_background_task`

### 记忆

`remember`、`recall`、`forget`

## 安全模型

Agent 能力很强，所以写操作有门禁：

1. **只读工具**（列表、读取、校验、干跑、报告）自由执行；同一轮连续只读调用并发。
2. **写操作**按模型给出的顺序串行。
3. **覆盖门禁**：新建同名模板/落地页/发件账号返回 `awaiting_user_confirmation`，不直接覆盖。操作员在控制台确认后，服务端用模型**原始参数**重放。
4. **高危写操作**：`create_sending_profile`、`create_campaign`、`restore_version`、`test_send` 一律确认。污点会话或 `PHISH_AGENT_STRICT_HIGH=1` 时，即使在本任务审批窗口内也要确认。
5. **计划门禁**：一次用户指令里的第 2 个写操作若未确认计划，会暂停等待 `propose_plan` 确认。
6. **污点门禁**：读过 `fetch_url`/`search_web`/`get_page`/`get_template` 的会话被视为已消费不可信内容，之后所有写操作都要确认。
7. **两段式发送**：`send_campaign` 只准备待确认项；操作员点「确认发送」才真正发信。
8. **精确重放**：确认项保存原始工具调用与参数；重新读取被污染的内容无法改写要执行的调用。

## 自检闭环

- `create_landing_page` / `update_landing_page` 保存后立即自检并返回 `validation.errors`。
- `send_campaign` 发送前复检落地页，有错误直接拒绝准备发送。
- `validate_page` / `dry_run_campaign` / `send_campaign` / 页面保存失败会追加系统提示，要求修复并重新自检（最多 3 次）。
- `e2e_check_page` 建临时对象、起进程内 HTTP 服务、用真实浏览器填写并提交表单，断言 submission 与跳转都记录后清理；需要本机 Chrome。
- `preview_page` 生成 JPEG 截图并附到下一轮上下文，模型可自己看布局问题（`PHISH_AGENT_VISION=0` 关闭）。

## 后台任务

`start_background_task`（或控制台「后台运行」）把自包含 prompt 写入 `agent_jobs`，worker 脱离浏览器执行：

- 默认 2 个 worker（`PHISH_AGENT_WORKERS` 1–8），30 分钟超时；
- `delay_minutes` 可定时跟进；
- 失败按 `PHISH_AGENT_JOB_RETRIES` 从会话记录重试（0–5，默认 0）；
- 等待确认的任务标记 `awaiting`，不假完成；
- 操作员确认/取消后自动从断点继续；
- 重启时 `queued`/`running` 重新排队；内存中的确认丢失，`awaiting` 任务标失败并提示重新发起；
- 同一会话只允许一个 Agent 运行（交互与后台互斥）。

## 子代理

`dispatch_subagents` 并行最多 4 个只读子循环（每个 6 轮、3 分钟、结论 2400 字符）。子代理只能使用注册表中 `ReadOnly` 的工具，不能递归，不能写库或发信。

## 任务清单与记忆

- `todo_write` / `todo_list`：会话级清单（≤20 项），存 `agent_todos`，每轮注入系统提示，上下文裁剪后仍能恢复。
- `remember` / `recall` / `forget`：跨会话 `agent_memories`，分类 preference/fact/task。不要存密码或密钥。

## 上下文预算

- 保留最新 60 条消息 / 6 万字符；被裁掉的轮次压缩成摘要。
- 交给模型的页面/模板 HTML 最多 4 万字符。
- 单个工具结果最多 1.2 万字符。
- 默认 24 轮工具往返（`PHISH_AGENT_MAX_ROUNDS` 4–64）。
- 进程被杀后载入历史时修复残缺的 tool-call 对。

## 服务商注意

- 流式使用 OpenAI 风格 SSE 与 `stream_options.include_usage`。
- 服务商拒绝图片输入时，自动改纯文本重试一次。
- `finish_reason=length` 视为错误（截断的页面/邮件比重试更糟）。
- Azure OpenAI 使用 `api-key` 头；客户端会识别 `*.openai.azure.com`。
- 工具调用按流式分片索引累积。
