# Claude Code adapter

Claude Code talks to Anthropic directly unless `ANTHROPIC_BASE_URL` points it somewhere else.
Pointed at LiteLLM it uses the Anthropic Messages route (`/v1/messages`), which the guard masks
and gates, streaming included.

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:4000
export ANTHROPIC_AUTH_TOKEN=sk-...          # your LiteLLM key
claude
```

Claude Code's shell tool is `Bash` (capital B) and takes `{"command": "..."}`, so the only
setting the guard needs is the tool name in `rules.yaml`:

```yaml
rewrite_tool: Bash
```

Without it the guard cannot find a tool to address the rewrite to and falls back to `strip`,
which still blocks but ends the model's turn instead of returning a tool result.

Claude Code sends no session header. The ledger still records every tool call and verdict; the
audit's "which upstream served the next request" join needs a session id, and on this route
LiteLLM also exposes no upstream metadata to the callback, so use the audit for the
transcript scan rather than the upstream attribution.
