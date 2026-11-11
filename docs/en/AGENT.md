# Console AI Agent

The console assistant is an OpenAI-compatible function-calling agent. It is optional: the platform works without an LLM. It can operate the platform directly instead of only producing text.

## Configuration

Settings → Model, or environment:

```bash
PHISH_LLM_BASE_URL=https://api.deepseek.com/v1
PHISH_LLM_KEY=your-key
PHISH_LLM_MODEL=deepseek-chat
# optional:
PHISH_LLM_PLAN_MODEL=deepseek-reasoner
PHISH_LLM_TEMPERATURE=0.7
PHISH_LLM_RATE_PER_MIN=30
```

Any OpenAI-compatible endpoint works (DeepSeek, OpenAI, Moonshot, local vLLM/Ollama). Local servers may leave the key empty.

## Tools (57)

Grouped by purpose. All names are stable; the registry lives in `internal/web/tools_registry.go`.

### Targets and groups

`list_groups`, `create_group`, `import_csv_to_group`, `audit_group`.

### Email templates and attachments

`list_templates`, `get_template`, `create_email_template`, `update_email_template`, `add_template_attachments`, `list_attachments`, `attach_attachment_to_template`.

### Landing pages and cloning

`list_pages`, `get_page`, `fetch_url`, `search_web`, `clone_site`, `create_landing_page`, `create_proxy_page`, `update_landing_page`, `patch_page`, `validate_page`, `preview_page`, `e2e_check_page`, `list_versions`, `restore_version`.

### Sending profiles and campaigns

`list_sending_profiles`, `test_send`, `create_sending_profile`, `create_campaign`, `add_campaign_targets`, `list_campaigns`, `dry_run_campaign`, `risk_report`, `send_campaign`, `list_send_failures`.

### Delivery truth and history

`send_history`, `send_status`, `search_chat_history`, `list_bounces`, `poll_bounces`.

### Suppression and search

`list_suppressions`, `add_suppression`, `remove_suppression`, `global_search`.

### Diagnostics

`get_health`, `read_logs`, `db_stats`, `geo_lookup`, `session_metrics`.

### Orchestration

`propose_plan`, `todo_write`, `todo_list`, `dispatch_subagents`, `start_background_task`.

### Memory

`remember`, `recall`, `forget`.

## Safety model

The agent is powerful, so writes are gated:

1. **Read-only tools** (lists, reads, validation, dry runs, reports) run freely. Consecutive read-only calls in one round run in parallel.
2. **Writes** run sequentially in the model's order.
3. **Overwrite gate** — creating a template/page/profile whose name already exists returns `awaiting_user_confirmation` instead of overwriting. The operator approves in the console; the server replays the model's **exact original arguments**.
4. **High-risk writes** — `create_sending_profile`, `create_campaign`, `restore_version`, `test_send` always require confirmation. A tainted session or `PHISH_AGENT_STRICT_HIGH=1` keeps them gated even inside an approved task window.
5. **Plan gate** — the second write in one user turn without an approved plan pauses for `propose_plan` confirmation.
6. **Taint gate** — reading `fetch_url`, `search_web`, `get_page`, `get_template` marks the session as having consumed untrusted content. From then on every write needs confirmation.
7. **Two-phase send** — `send_campaign` only prepares a pending confirmation. The operator clicks “Confirm send”; nothing is sent otherwise.
8. **Exact replay** — confirmations store the original tool call and arguments; re-reading poisoned content cannot change what runs.

## Self-check loop

- `create_landing_page` / `update_landing_page` validate immediately after saving and return `validation.errors`.
- `send_campaign` re-validates the landing page and refuses to prepare a send if it is broken.
- Failed `validate_page`, `dry_run_campaign`, `send_campaign` or page saves trigger a system nudge to fix and re-check (up to 3 times).
- `e2e_check_page` creates throwaway objects, starts an in-process HTTP server, drives a real browser through the form submission, asserts the submission was recorded and the redirect happened, then cleans up. Requires Chrome.
- `preview_page` returns a JPEG data URL attached to the next model turn so the model can inspect layout issues visually (`PHISH_AGENT_VISION=0` disables).

## Background jobs

`start_background_task` (or the console's “Run in background”) writes a self-contained prompt to `agent_jobs`. Workers run it detached from the browser:

- default 2 workers (`PHISH_AGENT_WORKERS` 1–8), 30-minute timeout;
- optional `delay_minutes` for follow-ups;
- failed jobs retry `PHISH_AGENT_JOB_RETRIES` times (0–5, default 0) from the transcript;
- a job parked on a confirmation is marked `awaiting`, not “done”;
- after the operator confirms/cancels, the job resumes automatically from the breakpoint;
- on restart, `queued`/`running` jobs are requeued; in-memory confirmations are lost and `awaiting` jobs are marked failed with a note;
- one agent run per session: interactive chat and background jobs are mutually exclusive.

## Subagents

`dispatch_subagents` runs up to 4 read-only child loops (6 rounds, 3 minutes each, 3000-character reports). Children can only use tools marked `ReadOnly` in the registry and cannot recurse. They never write or send.

## Todos and memory

- `todo_write` / `todo_list`: per-session checklist (≤20 items), persisted in `agent_todos`, injected into the system prompt so progress survives context trimming.
- `remember` / `recall` / `forget`: cross-session `agent_memories` with categories `preference` / `fact` / `task`. Do not store passwords or keys.

## Context budgets

- Keep the newest 60 messages / 60k runes; summarize dropped turns.
- Cap page/template HTML handed to the model at 40k runes.
- Cap one tool result at 12k runes.
- Default 24 tool rounds (`PHISH_AGENT_MAX_ROUNDS` 4–64).
- Repair dangling assistant tool-call pairs after a crash.

## Provider notes

- Streaming uses OpenAI-style SSE with `stream_options.include_usage`.
- If a provider rejects image content, the run retries text-only once.
- `finish_reason=length` is treated as an error (truncated page/email is worse than a retry).
- Azure OpenAI uses the `api-key` header; the client detects `*.openai.azure.com`.
- Tool calls are accumulated across stream fragments by index.
