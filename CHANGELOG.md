# Changelog

## 0.1.0 (2026-09-11)

First public release.

- `guard/`: LiteLLM callback. Masks secret values (plain, base64 at every alignment, URL-safe
  base64, hex) in outbound messages, gates tool calls in streaming and non-streaming responses
  against a hot-reloading rules file, writes a sqlite ledger of every tool call (name, sha256 and
  200-char prefix of the arguments, verdict, rule, upstream `api_base`, session) and every masked
  key name. `fail_mode: closed` by default: a guard error drops that reply's tool calls.
- `rules.example.yaml`: default ruleset (secret containers, allowlist bypasses, classic
  injection shapes) plus commented machine-specific examples.
- `audit/leak_audit.py`: retroactive scan of opencode's session store and Claude Code
  transcripts for secret values in tool results, joined against the router ledger to name the
  upstream that served the next request. Reports key names only.
- `adapters/opencode/`: a `tool.execute.before` plugin enforcing the same rules inside the
  harness, a converter that generates its rules from the guard's, and a per-agent permission
  profile that replaces `--auto`.
- `adapters/litellm/`: config snippet. `adapters/codex/`: provider config on the chat wire API plus
  the `rewrite_template` the array-form `shell` tool needs.
- Kill switches: `LLM_GUARD=off`, `LLM_GUARD_MODE=flag`, `LLM_GUARD_ON_BLOCK=strip`,
  `LLM_GUARD_FAIL=open`, `LLM_GUARD_RULES`, `LLM_GUARD_SECRET_FILES`, `LLM_GUARD_DB`.
- Masking reads `messages`, `system`, `input` and `instructions`. The gate screens all three
  response shapes LiteLLM serves: chat completion `tool_calls`, Responses API `function_call`
  items (events and the `response.completed` copy), and Anthropic `tool_use` blocks (SSE
  stream and non-stream). Verified against LiteLLM 1.98 and 1.100.
