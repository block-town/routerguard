"""LiteLLM callback: MASK outbound secrets, GATE inbound tool calls, LEDGER both.

Register in your LiteLLM proxy config:
    litellm_settings:
      callbacks:
        - guard.hooks.guard_instance

Kill switches: LLM_GUARD=off disables everything; LLM_GUARD_MODE=flag records
verdicts without blocking. Every path is wrapped; what happens on a guard bug is
`fail_mode`: closed (default) drops the tool calls of that turn, open passes them through.
"""
import asyncio
import copy
import json
import os
import re
import sys
import traceback

try:
    from litellm.integrations.custom_logger import CustomLogger
except ImportError:  # unit tests and tooling run without litellm installed
    class CustomLogger:  # pragma: no cover - stand-in with the surface this module uses
        def __init__(self, *args, **kwargs):
            pass

from . import ledger
from .gate import Gate, default_rules_path
from .secrets import SecretList, secret_paths

_OFF = os.environ.get("LLM_GUARD", "on").lower() == "off"
SESSION_HEADERS = ("x-session-id", "x-opencode-session")
_PLACEHOLDER_RX = re.compile(r"<<REDACTED:([A-Za-z0-9_]+)>>")
_VALUE_RULES = ("secret-value-in-args", "redacted-placeholder-exfil")


def _log(msg):
    print(f"[guard] {msg}", file=sys.stderr, flush=True)


def _ctx_from_request(data, stream=None, session_headers=SESSION_HEADERS):
    md = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    lmd = data.get("litellm_metadata") if isinstance(data.get("litellm_metadata"), dict) else {}
    headers = md.get("headers") or lmd.get("headers") or md.get("requester_custom_headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    hl = {str(k).lower(): v for k, v in headers.items()}
    return {
        "session_id": next((hl.get(h) for h in session_headers if hl.get(h)), None),
        "requested_model": md.get("requested_model") or data.get("model"),
        "model": data.get("model"),
        "stream": data.get("stream") if stream is None else stream,
    }


def _enrich(ctx, obj):
    hp = getattr(obj, "_hidden_params", None) or {}
    if isinstance(hp, dict):
        ctx["api_base"] = hp.get("api_base") or ctx.get("api_base")
        ctx["model_id"] = hp.get("model_id") or ctx.get("model_id")
        ctx["model"] = getattr(obj, "model", None) or ctx.get("model")
    return ctx


def _get(o, key, default=None):
    """Field access that works for dicts and for pydantic / namespace objects."""
    if isinstance(o, dict):
        return o.get(key, default)
    return getattr(o, key, default)


def _set(o, key, value):
    if isinstance(o, dict):
        o[key] = value
    else:
        setattr(o, key, value)


def _has_tool(data, name):
    """Is a tool called `name` offered in the request? Chat completions nest it under
    `function`; the Responses and Anthropic shapes carry `name` at the top level."""
    for tdef in data.get("tools") or []:
        if not isinstance(tdef, dict):
            continue
        fn = tdef.get("function")
        if (isinstance(fn, dict) and fn.get("name") == name) or tdef.get("name") == name:
            return True
    return False


def _shape(response):
    """chat | responses | anthropic | None, from the response object alone."""
    if isinstance(response, dict):
        if response.get("type") == "message" and isinstance(response.get("content"), list):
            return "anthropic"
        if isinstance(response.get("output"), list):
            return "responses"
        if isinstance(response.get("choices"), list):
            return "chat"
        return None
    if getattr(response, "choices", None) is not None:
        return "chat"
    if getattr(response, "output", None) is not None:
        return "responses"
    if getattr(response, "type", None) == "message" and getattr(response, "content", None) is not None:
        return "anthropic"
    return None


def _safe(s, default):
    return "".join(ch for ch in (s or default) if ch.isalnum() or ch in "_-") or default


def _block_text(tool_name, rule, names=()):
    """What the model reads after a block. No single quotes: it is echoed inside them."""
    head = f"[guard] Blocked tool call {_safe(tool_name, 'tool')} (rule: {_safe(rule, 'policy')})."
    names = [_safe(n, "") for n in names if _safe(n, "")]
    if names:
        return (f"{head} The value of {', '.join(names)} must never appear in a tool call. "
                f"Use the environment variable {', '.join('$' + n for n in names)} in commands, or a "
                f"${{{names[0]}}} reference in config files, and let the shell or the program resolve it. "
                f"Do not retry with the literal value; continue with the task.")
    return f"{head} This action is not permitted by policy; do not retry it, continue with the task."


def _fill(template, message):
    """Substitute {message} inside every string of a parsed JSON template."""
    if isinstance(template, str):
        return template.replace("{message}", message)
    if isinstance(template, list):
        return [_fill(v, message) for v in template]
    if isinstance(template, dict):
        return {k: _fill(v, message) for k, v in template.items()}
    return template


def _replacement_args(tool_name, rule, arg_key="command", names=(), template=None):
    """Arguments for the rewritten call. `template` is the parsed rewrite_template (a JSON value
    whose strings may contain {message}); without one, {arg_key: "echo '<message>'"}."""
    message = _block_text(tool_name, rule, names)
    if template is not None:
        return json.dumps(_fill(template, f"echo '{message}'" if isinstance(template, str) else message))
    return json.dumps({arg_key: f"echo '{message}'"})


# Request keys that carry conversation text, per API shape: chat completions (`messages`),
# Anthropic Messages (`messages`, `system`), Responses API (`input`, `instructions`).
_TEXT_KEYS = ("messages", "system", "input", "instructions")


def _mask_messages(messages, secrets, placeholder):
    """Replace secret values in every string under a request field. Returns {key: count}."""
    total = {}

    def walk(o):
        if isinstance(o, str):
            new, counts = secrets.mask(o, placeholder)
            for k, n in counts.items():
                total[k] = total.get(k, 0) + n
            return new
        if isinstance(o, dict):
            for k in list(o.keys()):
                o[k] = walk(o[k])
            return o
        if isinstance(o, list):
            for i in range(len(o)):
                o[i] = walk(o[i])
            return o
        return o
    if isinstance(messages, str):
        return secrets.mask(messages, placeholder)[1]   # caller assigns the masked string
    walk(messages)
    return total


def _mask_request(data, secrets, placeholder):
    """Mask every text-carrying field the request has. Returns {key: count} over all of them."""
    total = {}
    for key in _TEXT_KEYS:
        val = data.get(key)
        if isinstance(val, str):
            new, counts = secrets.mask(val, placeholder)
            data[key] = new
        elif isinstance(val, (list, dict)) and val:
            counts = _mask_messages(val, secrets, placeholder)
        else:
            continue
        for k, n in counts.items():
            total[k] = total.get(k, 0) + n
    return total


def _parse_template(raw):
    """rewrite_template: a JSON value (or a JSON string) with {message} where the echo goes.
    Example for Codex's shell tool: {"command": ["bash", "-lc", "echo '{message}'"]}."""
    if raw is None or raw == "":
        return None
    try:
        return json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        _log(f"rewrite_template is not valid JSON, ignoring: {raw!r}")
        return None


def _evtype(ev):
    """Event type as a string; LiteLLM uses enums for some Responses events."""
    t = _get(ev, "type")
    return str(getattr(t, "value", t) or "")


def _sse_events(chunk):
    """Split one SSE bytes chunk into [(event_name, parsed_json_or_None, raw_block)]."""
    text = chunk.decode("utf-8", "replace") if isinstance(chunk, (bytes, bytearray)) else str(chunk)
    out = []
    for block in text.split("\n\n"):
        if not block.strip():
            continue
        name, data = None, None
        for line in block.split("\n"):
            if line.startswith("event:"):
                name = line[6:].strip()
            elif line.startswith("data:"):
                data = line[5:].strip()
        try:
            obj = json.loads(data) if data is not None else None
        except Exception:
            obj = None
        out.append((name, obj, block))
    return out


def _sse_bytes(name, obj):
    return f"event: {name}\ndata: {json.dumps(obj)}\n\n".encode("utf-8")


class GuardHook(CustomLogger):
    def __init__(self, rules_path=None, on_block=None, db_path=None, secret_files=None, keepalive=None, fail_mode=None):
        super().__init__()
        self.gate = Gate(rules_path or default_rules_path())
        cfg = self.gate.cfg
        paths = secret_files if secret_files is not None else secret_paths(cfg)
        self.secrets = SecretList(paths)
        self.gate.secrets = self.secrets
        self.placeholder = cfg.get("mask_placeholder", "<<REDACTED:{name}>>")
        self.keepalive = float(keepalive if keepalive is not None else cfg.get("keepalive_seconds", 10))
        self.on_block = (on_block or os.environ.get("LLM_GUARD_ON_BLOCK") or cfg.get("on_block", "rewrite")).lower()  # rewrite | strip
        self.fail_mode = (fail_mode or os.environ.get("LLM_GUARD_FAIL") or cfg.get("fail_mode", "closed")).lower()  # closed | open
        self.rewrite_tool = cfg.get("rewrite_tool", "bash")
        self.rewrite_arg = cfg.get("rewrite_arg", "command")
        self.rewrite_template = _parse_template(cfg.get("rewrite_template"))
        self.session_headers = tuple(str(h).lower() for h in (cfg.get("session_headers") or SESSION_HEADERS))
        ledger.configure(db_path or os.environ.get("LLM_GUARD_DB") or cfg.get("ledger_db"))
        _log(f"loaded {len(self.gate.rules)} rules from {self.gate.path}, {len(self.secrets)} secret values from "
             f"{len(paths)} files, mode={self.gate.mode}, on_block={self.on_block}, fail={self.fail_mode}, "
             f"off={_OFF}, ledger={ledger.DB_PATH}")

    def _ctx(self, data, stream=None):
        return _ctx_from_request(data, stream, self.session_headers)

    def _names_for(self, rule, args):
        """Key names to mention in the block message when the block was about a value."""
        if rule not in _VALUE_RULES:
            return ()
        text = args if isinstance(args, str) else json.dumps(args or {})
        return tuple(sorted(set(self.secrets.contains(text)) | set(_PLACEHOLDER_RX.findall(text))))

    # ---------------------------------------------------------------- MASK
    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        if _OFF:
            return data
        try:
            counts = _mask_request(data, self.secrets, self.placeholder)
            if counts:
                ctx = self._ctx(data)
                ledger.masks(ctx, counts)
                _log(f"masked {sum(counts.values())} secret occurrence(s) "
                     f"[{', '.join(counts)}] session={ctx.get('session_id')}")
        except Exception:
            _log("pre_call error\n" + traceback.format_exc())
            if self.fail_mode == "closed":
                raise          # LiteLLM turns this into an error response; nothing leaves unmasked
        return data

    # ---------------------------------------------------------------- GATE (non-stream)
    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        if _OFF:
            return response
        try:
            shape = _shape(response)
            ctx = _enrich(self._ctx(data, stream=False), response)
            if shape == "responses":
                self._gate_responses(data, response, ctx)
                return response
            if shape == "anthropic":
                self._gate_anthropic(data, response, ctx)
                return response
            choices = getattr(response, "choices", None) or []
            if not choices:
                return response
            for choice in choices:
                msg = getattr(choice, "message", None)
                tcs = getattr(msg, "tool_calls", None) if msg is not None else None
                if not tcs:
                    continue
                keep, blocked = [], []
                for tc in tcs:
                    fn = getattr(tc, "function", None)
                    name = getattr(fn, "name", None) or ""
                    args = getattr(fn, "arguments", None) or ""
                    verdict, rule = self.gate.evaluate(name, args)
                    ledger.tool_call(ctx, name, args, verdict, rule)
                    if verdict == "block":
                        blocked.append((tc, name, rule, self._names_for(rule, args)))
                    else:
                        keep.append(tc)
                if blocked:
                    _log(f"BLOCKED {[(n, r) for _, n, r, _ in blocked]} session={ctx.get('session_id')} upstream={ctx.get('api_base')}")
                    if self.on_block == "rewrite" and _has_tool(data, self.rewrite_tool):
                        # keep the agent loop alive: the harness runs a harmless echo and the
                        # model sees the block as a tool result instead of the turn ending
                        for tc, name, rule, names in blocked:
                            fn = getattr(tc, "function", None)
                            if fn is not None:
                                fn.arguments = _replacement_args(name, rule, self.rewrite_arg, names, self.rewrite_template)
                                fn.name = self.rewrite_tool
                    else:
                        note = "".join("\n" + _block_text(n, r, names) for _, n, r, names in blocked)
                        msg.tool_calls = keep or None
                        msg.content = (msg.content or "") + note
                        if not keep:
                            choice.finish_reason = "stop"
        except Exception:
            _log("post_call error\n" + traceback.format_exc())
            if self.fail_mode == "closed":
                self._strip_all(response, "guard error")
        return response

    def _gate_responses(self, data, response, ctx):
        """Responses API: `output[]` items; tool calls are items of type function_call with
        `name` and an `arguments` JSON string. Rewrite in place or drop them."""
        items = _get(response, "output") or []
        keep, blocked = [], []
        for item in items:
            if _get(item, "type") != "function_call":
                keep.append(item)
                continue
            name = _get(item, "name") or ""
            args = _get(item, "arguments") or ""
            verdict, rule = self.gate.evaluate(name, args)
            ledger.tool_call(ctx, name, args, verdict, rule)
            if verdict == "block":
                blocked.append((item, name, rule, self._names_for(rule, args)))
            else:
                keep.append(item)
        if not blocked:
            return
        _log(f"BLOCKED(responses) {[(n, r) for _, n, r, _ in blocked]} session={ctx.get('session_id')} upstream={ctx.get('api_base')}")
        if self.on_block == "rewrite" and _has_tool(data, self.rewrite_tool):
            for item, name, rule, names in blocked:
                _set(item, "name", self.rewrite_tool)
                _set(item, "arguments", _replacement_args(name, rule, self.rewrite_arg, names, self.rewrite_template))
        else:
            note = "\n".join(_block_text(n, r, names) for _, n, r, names in blocked)
            keep.append({"type": "message", "id": "msg_guard", "role": "assistant", "status": "completed",
                         "content": [{"type": "output_text", "text": note, "annotations": []}]})
            _set(response, "output", keep)

    def _gate_anthropic(self, data, response, ctx):
        """Anthropic Messages: a dict with `content[]` blocks; tool calls are blocks of type
        tool_use with `name` and an `input` object. Rewrite in place or drop them."""
        blocks = _get(response, "content") or []
        keep, blocked = [], []
        for block in blocks:
            if _get(block, "type") != "tool_use":
                keep.append(block)
                continue
            name = _get(block, "name") or ""
            args = json.dumps(_get(block, "input") or {})
            verdict, rule = self.gate.evaluate(name, args)
            ledger.tool_call(ctx, name, args, verdict, rule)
            if verdict == "block":
                blocked.append((block, name, rule, self._names_for(rule, args)))
            else:
                keep.append(block)
        if not blocked:
            return
        _log(f"BLOCKED(anthropic) {[(n, r) for _, n, r, _ in blocked]} session={ctx.get('session_id')} upstream={ctx.get('api_base')}")
        if self.on_block == "rewrite" and _has_tool(data, self.rewrite_tool):
            for block, name, rule, names in blocked:
                _set(block, "name", self.rewrite_tool)
                _set(block, "input", json.loads(_replacement_args(name, rule, self.rewrite_arg, names, self.rewrite_template)))
        else:
            note = "\n".join(_block_text(n, r, names) for _, n, r, names in blocked)
            keep.append({"type": "text", "text": note})
            _set(response, "content", keep)
            if not any(_get(b, "type") == "tool_use" for b in keep):
                _set(response, "stop_reason", "end_turn")

    # ---------------------------------------------------------------- GATE (stream)
    async def async_post_call_streaming_iterator_hook(self, user_api_key_dict, response, request_data):
        if _OFF:
            async for item in response:
                yield item
            return
        it = response.__aiter__()
        try:
            first = await it.__anext__()
        except StopAsyncIteration:
            return

        async def rest():
            yield first
            async for c in it:
                yield c

        if isinstance(first, (bytes, bytearray)):
            handler = self._stream_anthropic          # LiteLLM relays /v1/messages as raw SSE bytes
        elif _evtype(first).startswith("response."):
            handler = self._stream_responses          # Responses API typed events
        else:
            handler = self._stream_chat               # chat completion chunks
        async for c in handler(rest(), request_data):
            yield c

    async def _stream_chat(self, response, request_data):
        ctx = self._ctx(request_data, stream=True)
        buffered = []          # chunks carrying tool-call deltas, in order
        finish_chunks = []     # chunks carrying finish_reason (held until the end)
        calls = {}             # index -> {"name": str, "args": [str], "id": str}
        last = None
        it = response.__aiter__()
        pending = None
        try:
            while True:
                if pending is None:
                    pending = asyncio.ensure_future(it.__anext__())
                done, _ = await asyncio.wait({pending}, timeout=self.keepalive if buffered else None)
                if not done:
                    # tool-call deltas are being held back; keep the client's chunk timer alive
                    if last is not None:
                        yield self._keepalive(last)
                    continue
                try:
                    chunk = pending.result()
                except StopAsyncIteration:
                    pending = None
                    break
                pending = None
                last = chunk
                _enrich(ctx, chunk)
                choices = getattr(chunk, "choices", None) or []
                has_tc = False
                finish = None
                for ch in choices:
                    delta = getattr(ch, "delta", None)
                    tcs = getattr(delta, "tool_calls", None) if delta is not None else None
                    if tcs:
                        has_tc = True
                        for tc in tcs:
                            idx = getattr(tc, "index", 0) or 0
                            slot = calls.setdefault(idx, {"name": "", "args": [], "id": None})
                            fn = getattr(tc, "function", None)
                            if fn is not None:
                                if getattr(fn, "name", None):
                                    slot["name"] += fn.name
                                if getattr(fn, "arguments", None):
                                    slot["args"].append(fn.arguments)
                            if getattr(tc, "id", None):
                                slot["id"] = tc.id
                    if getattr(ch, "finish_reason", None):
                        finish = ch.finish_reason
                if has_tc:
                    buffered.append(chunk)
                elif finish or buffered:
                    # once we hold tool chunks, everything after them stays ordered behind them
                    finish_chunks.append(chunk)
                else:
                    yield chunk
        except Exception:
            _log("stream error\n" + traceback.format_exc())
            for c in self._on_stream_failure(last, buffered, finish_chunks):
                yield c
            return

        # end of stream: evaluate the assembled calls
        try:
            verdicts = {}
            for idx, slot in calls.items():
                args = "".join(slot["args"])
                verdict, rule = self.gate.evaluate(slot["name"], args)
                ledger.tool_call(ctx, slot["name"], args, verdict, rule)
                verdicts[idx] = (verdict, rule, slot["name"], self._names_for(rule, args))
            blocked = {i for i, (v, _, _, _) in verdicts.items() if v == "block"}
            if blocked and self.on_block == "rewrite" and _has_tool(request_data, self.rewrite_tool):
                _log(f"BLOCKED(stream,rewrite) {[(verdicts[i][2], verdicts[i][1]) for i in blocked]} "
                     f"session={ctx.get('session_id')} upstream={ctx.get('api_base')}")
                emitted = set()
                for c in buffered:
                    for ch in getattr(c, "choices", None) or []:
                        delta = getattr(ch, "delta", None)
                        tcs = getattr(delta, "tool_calls", None) if delta is not None else None
                        if not tcs:
                            continue
                        new_tcs = []
                        for tc in tcs:
                            idx = getattr(tc, "index", 0) or 0
                            if idx not in blocked:
                                new_tcs.append(tc)
                            elif idx not in emitted:
                                emitted.add(idx)
                                fn = getattr(tc, "function", None)
                                if fn is not None:
                                    fn.name = self.rewrite_tool
                                    fn.arguments = _replacement_args(verdicts[idx][2], verdicts[idx][1], self.rewrite_arg, verdicts[idx][3], self.rewrite_template)
                                if getattr(tc, "id", None) is None:
                                    tc.id = calls[idx].get("id")
                                if getattr(tc, "type", None) is None:
                                    tc.type = "function"
                                new_tcs.append(tc)
                        delta.tool_calls = new_tcs or None
                    keep = any((getattr(ch.delta, "tool_calls", None) or getattr(ch.delta, "content", None))
                               for ch in (getattr(c, "choices", None) or []) if getattr(ch, "delta", None) is not None)
                    if keep:
                        yield c
                for c in finish_chunks:
                    yield c
            elif blocked:
                _log(f"BLOCKED(stream) {[(verdicts[i][2], verdicts[i][1]) for i in blocked]} "
                     f"session={ctx.get('session_id')} upstream={ctx.get('api_base')}")
                all_blocked = blocked == set(verdicts)
                for c in buffered:
                    for ch in getattr(c, "choices", None) or []:
                        delta = getattr(ch, "delta", None)
                        tcs = getattr(delta, "tool_calls", None) if delta is not None else None
                        if tcs:
                            delta.tool_calls = [tc for tc in tcs if (getattr(tc, "index", 0) or 0) not in blocked] or None
                    keep = any((getattr(ch.delta, "tool_calls", None) or getattr(ch.delta, "content", None))
                               for ch in (getattr(c, "choices", None) or []) if getattr(ch, "delta", None) is not None)
                    if keep:
                        yield c
                note = "".join("\n" + _block_text(verdicts[i][2], verdicts[i][1], verdicts[i][3]) for i in sorted(blocked))
                if last is not None:
                    yield self._note(last, note)
                for c in finish_chunks:
                    if all_blocked:
                        for ch in getattr(c, "choices", None) or []:
                            if getattr(ch, "finish_reason", None) == "tool_calls":
                                ch.finish_reason = "stop"
                    yield c
            else:
                for c in buffered + finish_chunks:
                    yield c
        except Exception:
            _log("stream verdict error\n" + traceback.format_exc())
            for c in self._on_stream_failure(last, buffered, finish_chunks):
                yield c

    # ---------------------------------------------------------------- GATE (stream, Responses API)
    async def _stream_responses(self, response, request_data):
        """Hold every event from a function_call item's `output_item.added` to its
        `output_item.done`, judge it, then release it rewritten, dropped, or as it was.
        The final `response.completed` event carries a copy of every item and is patched too."""
        ctx = self._ctx(request_data, stream=True)
        open_idx, held, deltas = None, [], []
        # LiteLLM regenerates item ids in the final `response.completed` copy, so blocked items
        # are remembered by id, by call_id, and by their original arguments.
        replaced, dropped = {}, set()      # key -> (name, arguments) | keys of removed items
        rewrite = self.on_block == "rewrite" and _has_tool(request_data, self.rewrite_tool)
        notes = []

        def item_of(ev):
            return _get(ev, "item")

        def keys_of(item, args=None):
            return {k for k in (_get(item, "id"), _get(item, "call_id"), ("args", args if args is not None else _get(item, "arguments"))) if k}

        def patch_completed(ev):
            resp = _get(ev, "response")
            out = _get(resp, "output") if resp is not None else None
            if not isinstance(out, list):
                return
            new = []
            for it in out:
                if _get(it, "type") == "function_call":
                    ks = keys_of(it)
                    if ks & dropped:
                        continue
                    hit = next((replaced[k] for k in ks if k in replaced), None)
                    if hit:
                        _set(it, "name", hit[0])
                        _set(it, "arguments", hit[1])
                new.append(it)
            if notes:
                new.append({"type": "message", "id": "msg_guard", "role": "assistant", "status": "completed",
                            "content": [{"type": "output_text", "text": "\n".join(notes), "annotations": []}]})
            _set(resp, "output", new)

        try:
            async for ev in response:
                _enrich(ctx, ev)
                t = _evtype(ev)
                if open_idx is None:
                    if t == "response.output_item.added" and _get(item_of(ev), "type") == "function_call":
                        open_idx, held, deltas = _get(ev, "output_index"), [ev], []
                        continue
                    if t == "response.completed":
                        patch_completed(ev)
                    yield ev
                    continue
                held.append(ev)
                idx = _get(ev, "output_index")
                if t == "response.function_call_arguments.delta" and idx == open_idx:
                    deltas.append(ev)
                    continue
                if t == "response.output_item.done" and idx == open_idx:
                    item = item_of(ev)
                    name = _get(item, "name") or ""
                    args = _get(item, "arguments") or "".join(str(_get(d, "delta") or "") for d in deltas)
                    verdict, rule = self.gate.evaluate(name, args)
                    ledger.tool_call(ctx, name, args, verdict, rule)
                    if verdict != "block":
                        for h in held:
                            yield h
                    elif rewrite:
                        new_args = _replacement_args(name, rule, self.rewrite_arg, self._names_for(rule, args), self.rewrite_template)
                        for k in keys_of(item, args):
                            replaced[k] = (self.rewrite_tool, new_args)
                        _log(f"BLOCKED(responses,stream,rewrite) {(name, rule)} session={ctx.get('session_id')} upstream={ctx.get('api_base')}")
                        first_delta = deltas[0] if deltas else None
                        for h in held:
                            ht = _evtype(h)
                            if ht == "response.function_call_arguments.delta" and _get(h, "output_index") == open_idx:
                                if h is not first_delta:
                                    continue              # one delta carries the whole replacement
                                _set(h, "delta", new_args)
                            elif ht == "response.function_call_arguments.done" and _get(h, "output_index") == open_idx:
                                _set(h, "arguments", new_args)
                            elif ht in ("response.output_item.added", "response.output_item.done") and _get(h, "output_index") == open_idx:
                                hi = item_of(h)
                                _set(hi, "name", self.rewrite_tool)
                                _set(hi, "arguments", new_args if ht.endswith("done") else "")
                            yield h
                    else:
                        dropped |= keys_of(item, args)
                        notes.append(_block_text(name, rule, self._names_for(rule, args)))
                        _log(f"BLOCKED(responses,stream) {(name, rule)} session={ctx.get('session_id')} upstream={ctx.get('api_base')}")
                        for h in held:            # release only what belongs to other items
                            if _get(h, "output_index") != open_idx:
                                yield h
                    open_idx, held, deltas = None, [], []
            if held:                                   # stream ended inside a function_call item
                args = "".join(str(_get(d, "delta") or "") for d in deltas)
                name = _get(item_of(held[0]), "name") or ""
                verdict, rule = self.gate.evaluate(name, args)
                ledger.tool_call(ctx, name, args, verdict, rule)
                if verdict != "block":
                    for h in held:
                        yield h
        except Exception:
            _log("responses stream error\n" + traceback.format_exc())
            if self.fail_mode != "closed":
                for h in held:
                    yield h

    # ---------------------------------------------------------------- GATE (stream, Anthropic Messages)
    async def _stream_anthropic(self, response, request_data):
        """LiteLLM relays /v1/messages streams as raw SSE bytes. Hold a tool_use content block
        from its start to its stop, judge it, then release it rewritten, replaced by a text
        block, or as it was. `message_delta` gets stop_reason end_turn if nothing runnable is left."""
        ctx = self._ctx(request_data, stream=True)
        open_index, held, partial = None, [], []
        kept_tool, stripped = False, False
        rewrite = self.on_block == "rewrite" and _has_tool(request_data, self.rewrite_tool)
        it = response.__aiter__()
        pending = None
        try:
            while True:
                if pending is None:
                    pending = asyncio.ensure_future(it.__anext__())
                done, _ = await asyncio.wait({pending}, timeout=self.keepalive if held else None)
                if not done:
                    yield _sse_bytes("ping", {"type": "ping"})
                    continue
                try:
                    chunk = pending.result()
                except StopAsyncIteration:
                    pending = None
                    break
                pending = None
                if not isinstance(chunk, (bytes, bytearray)):
                    yield chunk
                    continue
                for name, obj, raw in _sse_events(chunk):
                    if obj is None:
                        yield (raw + "\n\n").encode("utf-8")
                        continue
                    t = obj.get("type")
                    if open_index is None:
                        if t == "content_block_start" and (obj.get("content_block") or {}).get("type") == "tool_use":
                            open_index, held, partial = obj.get("index"), [(name, obj)], []
                            continue
                        if t == "message_delta" and stripped and not kept_tool:
                            (obj.get("delta") or {})["stop_reason"] = "end_turn"
                        yield _sse_bytes(name or t, obj)
                        continue
                    held.append((name, obj))
                    if t == "content_block_delta" and obj.get("index") == open_index:
                        partial.append(str((obj.get("delta") or {}).get("partial_json") or ""))
                        continue
                    if t == "content_block_stop" and obj.get("index") == open_index:
                        start = held[0][1]["content_block"]
                        tool, tid = start.get("name") or "", start.get("id")
                        args = "".join(partial) or "{}"
                        verdict, rule = self.gate.evaluate(tool, args)
                        ledger.tool_call(ctx, tool, args, verdict, rule)
                        if verdict != "block":
                            kept_tool = True
                            for n, o in held:
                                yield _sse_bytes(n or o.get("type"), o)
                        elif rewrite:
                            new_args = _replacement_args(tool, rule, self.rewrite_arg, self._names_for(rule, args), self.rewrite_template)
                            _log(f"BLOCKED(anthropic,stream,rewrite) {(tool, rule)} session={ctx.get('session_id')} upstream={ctx.get('api_base')}")
                            kept_tool = True
                            yield _sse_bytes("content_block_start", {"type": "content_block_start", "index": open_index,
                                             "content_block": {"type": "tool_use", "id": tid, "name": self.rewrite_tool, "input": {}}})
                            yield _sse_bytes("content_block_delta", {"type": "content_block_delta", "index": open_index,
                                             "delta": {"type": "input_json_delta", "partial_json": new_args}})
                            yield _sse_bytes("content_block_stop", {"type": "content_block_stop", "index": open_index})
                        else:
                            stripped = True
                            _log(f"BLOCKED(anthropic,stream) {(tool, rule)} session={ctx.get('session_id')} upstream={ctx.get('api_base')}")
                            note = _block_text(tool, rule, self._names_for(rule, args))
                            yield _sse_bytes("content_block_start", {"type": "content_block_start", "index": open_index,
                                             "content_block": {"type": "text", "text": ""}})
                            yield _sse_bytes("content_block_delta", {"type": "content_block_delta", "index": open_index,
                                             "delta": {"type": "text_delta", "text": note}})
                            yield _sse_bytes("content_block_stop", {"type": "content_block_stop", "index": open_index})
                        open_index, held, partial = None, [], []
            if held and self.fail_mode != "closed":       # stream ended inside a tool_use block
                for n, o in held:
                    yield _sse_bytes(n or o.get("type"), o)
        except Exception:
            _log("anthropic stream error\n" + traceback.format_exc())
            if self.fail_mode != "closed":
                for n, o in held:
                    yield _sse_bytes(n or o.get("type"), o)

    def _on_stream_failure(self, last, buffered, finish_chunks):
        """Chunks to emit after a guard exception mid-stream. open: everything held, untouched.
        closed: the held tool-call chunks are dropped, a note is emitted, the turn ends."""
        if self.fail_mode != "closed":
            return buffered + finish_chunks
        out = []
        if last is not None:
            out.append(self._note(last, "\n[guard] Guard error while screening this reply; its tool calls were dropped."))
        for c in finish_chunks:
            for ch in getattr(c, "choices", None) or []:
                if getattr(ch, "finish_reason", None) == "tool_calls":
                    ch.finish_reason = "stop"
            out.append(c)
        return out

    @staticmethod
    def _strip_all(response, why):
        """Remove every tool call from a non-streaming response, whatever its shape (fail-closed path)."""
        try:
            note = f"[guard] {why}; the tool calls in this reply were dropped."
            shape = _shape(response)
            if shape == "responses":
                keep = [i for i in (_get(response, "output") or []) if _get(i, "type") != "function_call"]
                keep.append({"type": "message", "id": "msg_guard", "role": "assistant", "status": "completed",
                             "content": [{"type": "output_text", "text": note, "annotations": []}]})
                _set(response, "output", keep)
                return
            if shape == "anthropic":
                keep = [b for b in (_get(response, "content") or []) if _get(b, "type") != "tool_use"]
                keep.append({"type": "text", "text": note})
                _set(response, "content", keep)
                _set(response, "stop_reason", "end_turn")
                return
            for choice in getattr(response, "choices", None) or []:
                msg = getattr(choice, "message", None)
                if msg is None or not getattr(msg, "tool_calls", None):
                    continue
                msg.tool_calls = None
                msg.content = (msg.content or "") + "\n" + note
                choice.finish_reason = "stop"
        except Exception:
            _log("strip_all error\n" + traceback.format_exc())

    @staticmethod
    def _keepalive(last):
        c = copy.deepcopy(last)
        for ch in getattr(c, "choices", None) or []:
            ch.finish_reason = None
            if getattr(ch, "delta", None) is not None:
                ch.delta.content = ""
                ch.delta.tool_calls = None
                if hasattr(ch.delta, "reasoning_content"):
                    ch.delta.reasoning_content = None
        if hasattr(c, "usage"):
            c.usage = None
        return c

    @staticmethod
    def _note(last, text):
        c = GuardHook._keepalive(last)
        for ch in getattr(c, "choices", None) or []:
            if getattr(ch, "delta", None) is not None:
                ch.delta.content = text
                ch.delta.role = "assistant"
        return c


guard_instance = GuardHook()
