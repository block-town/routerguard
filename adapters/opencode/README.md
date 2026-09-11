# opencode adapter

Two harness-side pieces that complement the router-side guard. The router guard only sees
traffic that goes through LiteLLM; these cover the rest.

## 1. `guard-plugin.js`: block before execution

An opencode plugin on the [`tool.execute.before` hook](https://opencode.ai/docs/plugins/). It evaluates the same rule shape as the
router gate against the tool name and every string argument, throws on `block` (opencode
reports the failure to the model and the loop continues), and appends a JSON line per hit to
`~/.local/share/opencode/guard.log`.

```sh
mkdir -p ~/.config/opencode/plugins
cp adapters/opencode/guard-plugin.js ~/.config/opencode/plugins/
python adapters/opencode/rules_to_json.py rules.yaml > ~/.config/opencode/guard-rules.json   # optional: share the ruleset
```

Without `guard-rules.json` the built-in defaults (a copy of `rules.example.yaml` minus the
secret-value rule) apply. The file is re-read every 30 s.

What it cannot do: it has no secret list, so `__SECRET_VALUE__` rules are skipped. Outbound
masking stays the router's job. Like the ledger, the log keeps a 200-char prefix of the
arguments per hit: treat it as a local log file.

## 2. `permission-profile.example.json`: replace `--auto`

opencode supports a `permission` block per agent, which overrides the global one. The example
shows an interactive global profile (read-only commands allowed, secret containers denied,
everything else asks) and an unattended `worker` agent with an enumerated allowlist. Launch
unattended work as

```sh
opencode run --agent worker "take the next item"
```

instead of `opencode run --auto`. In non-interactive mode an `ask` is auto-rejected, so the
explicit `deny` entries only make the intent visible. An injected tool call then fails closed
whichever upstream served it.

Two details that matter:

- **`echo *` must be allowed** in any profile that runs behind a guard with `on_block: rewrite`;
  the rewritten call is an echo.
- **Globs match last-match-wins.** Put denies after allows or the allow is dead.
