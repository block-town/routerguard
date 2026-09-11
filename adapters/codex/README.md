# Codex adapter

Codex reaches a custom provider over one of two wire APIs, `chat` or `responses`. Both are
covered (mask, gate, ledger). On the `responses` stream LiteLLM exposes no upstream metadata to
the callback, so the ledger's `api_base` column is empty for those rows; pick `chat` if you want
it filled.

`~/.codex/config.toml`:

```toml
model = "auto"
model_provider = "litellm"

[model_providers.litellm]
name = "LiteLLM"
base_url = "http://127.0.0.1:4000/v1"
env_key = "LITELLM_KEY"          # export LITELLM_KEY=sk-...
wire_api = "chat"
```

Codex's tool is `shell` and its arguments are `{"command": ["bash", "-lc", "..."], ...}`, an
array rather than a string, so the default echo rewrite would fail its schema. Set these in
`rules.yaml`:

```yaml
rewrite_tool: shell
rewrite_template: '{"command": ["bash", "-lc", "echo ''{message}''"], "timeout_ms": 5000}'
```

The gate matches every string inside the array, so `cat .env` inside `["bash", "-lc", "cat .env"]`
is caught exactly as it would be as a plain string.

Codex sends no session header. Add one if your setup can (`x-session-id`), or accept that the
ledger cannot tie a leak to the upstream that served the next request.
