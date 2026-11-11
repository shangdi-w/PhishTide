package web

// The agent tool registry. Every callable operation is declared once here with
// its JSON schema and a ReadOnly flag. The execution switch in agent.go binds
// handlers; the loop itself, parallelism and the read-only sub-agent toolset all
// derive from this table, so adding a tool never touches the loop.

import (
	"encoding/json"

	"phishsim/internal/features/llm"
)

type agentToolSpec struct {
	Def      llm.Tool
	ReadOnly bool
}

func (s agentToolSpec) name() string { return s.Def.Function.Name }

func toolSchema(s string) json.RawMessage { return json.RawMessage(s) }

func toolObj(props, required string) json.RawMessage {
	if required == "" {
		return toolSchema(`{"type":"object","properties":{` + props + `},"additionalProperties":false}`)
	}
	return toolSchema(`{"type":"object","properties":{` + props + `},"required":[` + required + `],"additionalProperties":false}`)
}

const (
	argStr     = `{"type":"string"}`
	argInt     = `{"type":"integer"}`
	argIDArr   = `{"type":"array","items":{"type":"integer"}}`
	argTargets = `{"type":"array","items":{"type":"object","properties":{"email":{"type":"string"},"first_name":{"type":"string"},"last_name":{"type":"string"},"position":{"type":"string"},"department":{"type":"string"}},"required":["email"]}}`
)

func tool(name, desc string, params json.RawMessage, readOnly bool) agentToolSpec {
	return agentToolSpec{
		Def:      llm.Tool{Type: "function", Function: llm.ToolFunction{Name: name, Description: desc, Parameters: params}},
		ReadOnly: readOnly,
	}
}

var agentToolSpecs = []agentToolSpec{
	tool("list_groups", "列出所有目标组及其人数", toolObj("", ""), true),
	tool("create_group", "创建目标组并写入收件人", toolObj(`"name":`+argStr+`,"targets":`+argTargets, `"name","targets"`), false),
	tool("import_csv_to_group", "把会话中上传的 CSV/TXT 名单导入为新目标组（表头支持 email/first_name/last_name/position/department 或中文）", toolObj(`"group_name":`+argStr+`,"upload_id":`+argInt, `"group_name","upload_id"`), false),
	tool("audit_group", "名单体检：格式、重复、共享/职能邮箱、一次性邮箱、域名 MX；check_mx=false 可跳过 DNS", toolObj(`"group_id":`+argInt+`,"check_mx":{"type":"boolean"}`, `"group_id"`), true),
	tool("list_templates", "列出邮件模板（id、名称、主题、附件数）", toolObj("", ""), true),
	tool("get_template", "读取一个邮件模板的完整内容", toolObj(`"template_id":`+argInt, `"template_id"`), true),
	tool("create_email_template", "新建或覆盖同名邮件模板；可附带会话上传的附件。覆盖已有同名模板前需要操作员确认", toolObj(`"name":`+argStr+`,"subject":`+argStr+`,"html":`+argStr+`,"text":`+argStr+`,"upload_ids":`+argIDArr, `"name","subject","html"`), false),
	tool("update_email_template", "按 id 修改邮件模板（只改传入的字段）", toolObj(`"template_id":`+argInt+`,"name":`+argStr+`,"subject":`+argStr+`,"html":`+argStr+`,"text":`+argStr, `"template_id"`), false),
	tool("add_template_attachments", "把会话上传的文件挂到邮件模板", toolObj(`"template_id":`+argInt+`,"upload_ids":`+argIDArr, `"template_id","upload_ids"`), false),
	tool("list_attachments", "列出隔离附件库（只返回元数据：名称/大小/SHA-256/备注，不含内容）", toolObj("", ""), true),
	tool("attach_attachment_to_template", "把附件库里的文件挂到邮件模板（平台不解压不执行）；模板已有同名附件或达到 5 个上限时会失败", toolObj(`"attachment_id":`+argInt+`,"template_id":`+argInt, `"attachment_id","template_id"`), false),
	tool("list_pages", "列出钓鱼落地页（id、名称、类型）", toolObj("", ""), true),
	tool("get_page", "读取落地页 HTML（超过 4 万字符会截断并注明）", toolObj(`"page_id":`+argInt, `"page_id"`), true),
	tool("fetch_url", "抓取参考网站 HTML（标题、配色、字体、表单结构），用于仿制或美化；render=true 用无头浏览器渲染 SPA；只读", toolObj(`"url":`+argStr+`,"render":{"type":"boolean"}`, `"url"`), true),
	tool("search_web", "用部署方配置的 SearXNG 搜索参考页面；未配置时返回提示", toolObj(`"query":`+argStr+`,"limit":`+argInt, `"query"`), true),
	tool("clone_site", "把目标站完整克隆为落地页快照（HTML + 同源资源，SPA 可抓接口本地重放）；只需要实时转发时用 create_proxy_page。static_form=true 会去掉 JS 只保留表单", toolObj(`"name":`+argStr+`,"url":`+argStr+`,"static_form":{"type":"boolean"},"error_message":`+argStr+`,"capture_credentials":{"type":"boolean"},"capture_passwords":{"type":"boolean"},"redirect_url":`+argStr, `"name","url"`), false),
	tool("create_landing_page", "用 HTML 新建落地页；表单 action 应为 __SUBMIT_URL__。error_message 填与页面语言/品牌一致的登录失败提示（如英文页用英文）；覆盖已有同名页面需要操作员确认，保存后自动自检", toolObj(`"name":`+argStr+`,"html":`+argStr+`,"error_message":`+argStr+`,"capture_credentials":{"type":"boolean"},"capture_passwords":{"type":"boolean"},"redirect_url":`+argStr, `"name","html"`), false),
	tool("create_proxy_page", "创建反向代理落地页：实时转发目标站点（含 API 与登录请求），适合 SPA；提交密码时平台捕获并本地应答，绝不把凭证转发给真实站点。error_message 填与上游页面一致的失败提示；演练期间上游必须可达", toolObj(`"name":`+argStr+`,"url":`+argStr+`,"error_message":`+argStr+`,"capture_credentials":{"type":"boolean"},"capture_passwords":{"type":"boolean"},"redirect_url":`+argStr, `"name","url"`), false),
	tool("update_landing_page", "按 id 修改落地页 HTML 或属性（美化网站用这个）；error_message 不传则保留原值；保存后自动自检", toolObj(`"page_id":`+argInt+`,"name":`+argStr+`,"html":`+argStr+`,"error_message":`+argStr+`,"capture_credentials":{"type":"boolean"},"capture_passwords":{"type":"boolean"},"redirect_url":`+argStr, `"page_id"`), false),
	tool("patch_page", "对已有落地页做局部修改（省 token）：find/replace 文本替换（all=true 全部替换）或 css 注入；比重写整页更安全，保存后自动自检", toolObj(`"page_id":`+argInt+`,"find":`+argStr+`,"replace":`+argStr+`,"all":{"type":"boolean"},"css":`+argStr, `"page_id"`), false),
	tool("validate_page", "自检落地页：表单 action、输入字段、__SUBMIT_URL__、密码框、外部资源、凭证捕获开关是否一致；check_links=true 时并发探测外部链接", toolObj(`"page_id":`+argInt+`,"check_links":{"type":"boolean"}`, `"page_id"`), true),
	tool("preview_page", "用无头浏览器渲染落地页并生成全页截图；截图会直接作为图片交给模型查看，同时返回后台截图地址与像素尺寸", toolObj(`"page_id":`+argInt, `"page_id"`), true),
	tool("e2e_check_page", "端到端自检落地页：无头浏览器真实打开页面、填写并提交表单，确认平台捕获到提交与跳转（需本机 Chrome，约 5–30 秒）；静态自检通过后再用", toolObj(`"page_id":`+argInt, `"page_id"`), true),
	tool("list_versions", "列出邮件模板或落地页的历史版本（新到旧，最多 20 条）；kind 取 email_template 或 landing_page", toolObj(`"kind":`+argStr+`,"object_id":`+argInt+`,"limit":`+argInt, `"kind","object_id"`), true),
	tool("restore_version", "把邮件模板/落地页回滚到指定历史版本；回滚本身也会记为新版本，可再次回滚撤销", toolObj(`"version_id":`+argInt, `"version_id"`), false),
	tool("list_sending_profiles", "列出发件账号（不含密码）", toolObj("", ""), true),
	tool("test_send", "用指定发件账号给发件邮箱发一封测试邮件（只发一封，不产生活动记录）", toolObj(`"profile_id":`+argInt+`,"template_id":`+argInt+`,"to":`+argStr, `"profile_id"`), false),
	tool("create_sending_profile", "创建或更新发件账号（SMTP 邮箱/密码/端口）；host 可省略，按邮箱域名推断；端口默认 587。覆盖同名账号前需要操作员确认", toolObj(`"name":`+argStr+`,"host":`+argStr+`,"port":`+argInt+`,"username":`+argStr+`,"password":`+argStr+`,"tls_mode":`+argStr+`,"from_name":`+argStr+`,"from_email":`+argStr, `"name","username","password"`), false),
	tool("create_campaign", "创建演练活动（绑定模板、落地页、目标组、发件账号）；可选 A/B 双模板、链接有效期/一次性、IP 允许拒绝名单、种子收件人", toolObj(`"name":`+argStr+`,"template_id":`+argInt+`,"email_template_b_id":`+argInt+`,"ab_split":`+argInt+`,"landing_page_id":`+argInt+`,"group_ids":`+argIDArr+`,"sending_profile_id":`+argInt+`,"link_ttl_hours":`+argInt+`,"link_once":{"type":"boolean"},"ip_allow":`+argStr+`,"ip_deny":`+argStr+`,"seed_emails":`+argStr, `"name","template_id","landing_page_id","group_ids"`), false),
	tool("add_campaign_targets", "给已有活动追加收件人（email 必填，可选 first_name/last_name/position/department）；已存在的邮箱自动跳过，新增目标存入活动独立名单，不影响原目标组", toolObj(`"campaign_id":`+argInt+`,"targets":`+argTargets, `"campaign_id","targets"`), false),
	tool("list_campaigns", "列出活动及发送/打开/点击/提交统计", toolObj("", ""), true),
	tool("dry_run_campaign", "干跑活动：渲染预览，检查模板/落地页自检/发件账号/待发人数/SPF-DKIM-DMARC，不发信；e2e=true 时额外用无头浏览器提交一次落地页表单", toolObj(`"campaign_id":`+argInt+`,"e2e":{"type":"boolean"}`, `"campaign_id"`), true),
	tool("risk_report", "按活动生成个人与部门风险评分报告（打开/点击/提交/报告），返回高风险名单与报告链接", toolObj(`"campaign_id":`+argInt+`,"limit":`+argInt, `"campaign_id"`), true),
	tool("send_campaign", "请求发送活动邮件；发送前会强制复检落地页，未通过则拒绝；通过后弹给用户确认，确认后才真正发送", toolObj(`"campaign_id":`+argInt, `"campaign_id"`), false),
	tool("list_send_failures", "列出活动的发送失败记录（每个收件人最后一次失败的分类与原始报错），用于诊断为什么没发出去", toolObj(`"campaign_id":`+argInt+`,"limit":`+argInt, `"campaign_id"`), true),
	tool("global_search", "跨模块全文检索：历史会话、邮件模板、落地页、活动、发送台账、提交记录；结果已脱敏", toolObj(`"query":`+argStr+`,"limit":`+argInt, `"query"`), true),
	tool("list_suppressions", "列出跨活动抑制名单（硬退/退订/手动），发送时这些地址会被自动跳过", toolObj("", ""), true),
	tool("add_suppression", "把邮箱加入抑制名单，之后所有活动发送都会跳过；reason 取 manual/hard_bounce/unsubscribe/complaint", toolObj(`"email":`+argStr+`,"reason":`+argStr+`,"note":`+argStr, `"email"`), false),
	tool("remove_suppression", "从抑制名单移除邮箱（之后会重新接收邮件）", toolObj(`"email":`+argStr, `"email"`), false),
	tool("send_history", "查询发送台账（活动删除后仍保留）：按邮箱/活动名/主题关键字或 campaign_id 查最近发送与失败记录；回答『发没发出去』前必须先查", toolObj(`"query":`+argStr+`,"campaign_id":`+argInt+`,"limit":`+argInt, ""), true),
	tool("send_status", "发送状态判定（优先用它回答『发没发』）：按活动名/活动 ID/邮箱 → verdict=sent|failed|unknown、发送数量、first_sent_at 与逐条证据（台账/现存活动/已删除活动/历史回执）", toolObj(`"campaign_id":`+argInt+`,"campaign_name":`+argStr+`,"email":`+argStr, ""), true),
	tool("search_chat_history", "搜索历史会话里助手/工具留下的回执（只搜 assistant/tool，不搜用户输入），用于台账上线之前的老发送；关键字可传活动名或「已发送活动」", toolObj(`"query":`+argStr+`,"limit":`+argInt, `"query"`), true),
	tool("list_bounces", "列出退信（DSN）记录：硬退（5.x.x 地址无效）/ 软退（4.x.x 临时）/ 投递成功；campaign_id 传 0 查看全部", toolObj(`"campaign_id":`+argInt+`,"limit":`+argInt, ""), true),
	tool("poll_bounces", "立即收取退信邮箱（IMAP）里的未读投递状态通知并入库，自动把硬退标记到对应收件人", toolObj(`"limit":`+argInt, ""), false),
	tool("geo_lookup", "查 IP 归属地（离线 ip2asn 库，被动查询）：返回国家与运营商/ASN；支持逗号分隔多个 IPv4，内网/环回地址返回未命中", toolObj(`"ip":`+argStr, `"ip"`), true),
	tool("get_health", "平台健康检查（只读）：数据库连通与连接数、各表数据量、发送任务状态、LLM/Geo 配置、进程运行时长", toolObj("", ""), true),
	tool("read_logs", "读取最近应用日志（只读，凭据类字段已脱敏）：level 取 info/warn/error，limit 默认 50 最多 200，contains 按关键字过滤", toolObj(`"level":`+argStr+`,"limit":`+argInt+`,"contains":`+argStr, ""), true),
	tool("db_stats", "数据库各表行数统计（只读），用于快速判断数据量与异常增长", toolObj("", ""), true),
	tool("start_background_task", "把一段自包含的任务提交到后台队列执行（关掉页面也会继续），完成后结果写入会话；delay_minutes>0 可定时跟进（如 24 小时后汇总）；prompt 要写清目标、对象与约束", toolObj(`"prompt":`+argStr+`,"delay_minutes":`+argInt, `"prompt"`), false),
	tool("session_metrics", "读取本会话的 Agent 用量统计：运行次数、轮次、工具调用/失败数、token 总量与上次耗时", toolObj("", ""), true),
	tool("propose_plan", "多步任务先提交执行计划（至少 2 步），操作员确认后系统才允许连续写操作；步骤要具体到对象与顺序", toolObj(`"steps":{"type":"array","items":{"type":"string"}}`, `"steps"`), false),
	tool("todo_write", "写入/更新本会话的任务清单（整表替换，最多 20 项）；多步骤任务先建清单，并在每个阶段更新状态", toolObj(`"items":{"type":"array","items":{"type":"object","properties":{"text":`+argStr+`,"status":{"type":"string","enum":["pending","in_progress","done"]}},"required":["text"]}}`, `"items"`), false),
	tool("todo_list", "读取本会话当前任务清单", toolObj("", ""), true),
	tool("dispatch_subagents", "并行派出只读子代理核验独立问题（页面自检、名单体检、DNS/链接、活动数据）；子代理不能写库或发信；最多 4 个，每个返回结论与证据", toolObj(`"tasks":{"type":"array","items":{"type":"object","properties":{"title":`+argStr+`,"instruction":`+argStr+`},"required":["instruction"]}}`, `"tasks"`), false),
	tool("remember", "保存跨会话长期记忆：category 取 preference(偏好)/fact(事实)/task(任务)，不要保存密码或密钥", toolObj(`"key":`+argStr+`,"value":`+argStr+`,"category":`+argStr, `"key","value"`), false),
	tool("recall", "检索长期记忆；query 为空时列出最近条目，category 可按 preference/fact/task 过滤", toolObj(`"query":`+argStr+`,"category":`+argStr+`,"limit":`+argInt, ``), true),
	tool("forget", "删除一条长期记忆", toolObj(`"key":`+argStr, `"key"`), false),
}

func agentTools() []llm.Tool {
	out := make([]llm.Tool, 0, len(agentToolSpecs))
	for _, s := range agentToolSpecs {
		out = append(out, s.Def)
	}
	return out
}

// agentToolMeta looks a tool up in the registry.
func agentToolMeta(name string) (agentToolSpec, bool) {
	for _, s := range agentToolSpecs {
		if s.name() == name {
			return s, true
		}
	}
	return agentToolSpec{}, false
}

// readOnlyAgentTools returns the tool subset a read-only sub-agent may use. It
// deliberately excludes dispatch_subagents so sub-agents cannot recurse.
func readOnlyAgentTools() []llm.Tool {
	out := make([]llm.Tool, 0, len(agentToolSpecs))
	for _, s := range agentToolSpecs {
		if s.ReadOnly && s.name() != "dispatch_subagents" {
			out = append(out, s.Def)
		}
	}
	return out
}
