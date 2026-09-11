"""Tool-call gate: pure decision logic. Loads the rules file once, hot-reloads on mtime."""
import json
import os
import re
import time

import yaml

PKG = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(PKG)


def default_rules_path():
    """LLM_GUARD_RULES, else <repo>/rules.yaml, else the shipped <repo>/rules.example.yaml."""
    env = os.environ.get("LLM_GUARD_RULES")
    if env:
        return os.path.expanduser(env)
    for name in ("rules.yaml", "rules.example.yaml"):
        p = os.path.join(REPO, name)
        if os.path.exists(p):
            return p
    return os.path.join(REPO, "rules.example.yaml")


class Rule:
    __slots__ = ("id", "action", "rx", "special")

    def __init__(self, d):
        self.id = d["id"]
        self.action = d.get("action", "flag")
        pat = d["pattern"]
        self.special = pat if pat.startswith("__") else None
        self.rx = None if self.special else re.compile(pat, re.I | re.M)


class Gate:
    _RELOAD_S = 30

    def __init__(self, path=None, secrets=None):
        self.path = path or default_rules_path()
        self.secrets = secrets
        self.mode = os.environ.get("LLM_GUARD_MODE", "block").lower()   # block | flag
        self._mtime = None
        self._checked = 0.0
        self.cfg, self.rules = {}, []
        self._load()

    def _load(self):
        with open(self.path) as f:
            cfg = yaml.safe_load(f) or {}
        rules = [Rule(r) for r in cfg.get("rules", [])]   # compile first: a bad edit never replaces good rules
        self.cfg, self.rules = cfg, rules
        self._mtime = os.stat(self.path).st_mtime_ns

    def reload_if_changed(self):
        """Hot-reload the rules file when its mtime changes (checked at most every 30s)."""
        now = time.time()
        if now - self._checked < self._RELOAD_S:
            return False
        self._checked = now
        try:
            if os.stat(self.path).st_mtime_ns != self._mtime:
                self._load()
                return True
        except Exception:
            pass
        return False

    @staticmethod
    def _strings(arguments):
        """Every decoded string value (so \\u-escapes and \\n can't hide a pattern);
        the raw text only when the arguments are not valid JSON."""
        try:
            obj = json.loads(arguments) if isinstance(arguments, str) else arguments
        except Exception:
            return [arguments or ""]
        out = []

        def walk(o):
            if isinstance(o, str):
                out.append(o)
            elif isinstance(o, dict):
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(obj)
        return out or [arguments if isinstance(arguments, str) else json.dumps(arguments)]

    def evaluate(self, tool_name, arguments):
        """Return (verdict, rule_id): verdict in allow | flag | block."""
        self.reload_if_changed()
        texts = self._strings(arguments)
        haystack = "\n".join([tool_name or ""] + texts)
        verdict, hit = "allow", None
        for r in self.rules:
            if r.special == "__SECRET_VALUE__":
                matched = self.secrets is not None and bool(self.secrets.contains(haystack))
            else:
                matched = bool(r.rx.search(haystack))
            if not matched:
                continue
            if r.action == "block":
                return ("block" if self.mode == "block" else "flag"), r.id
            if verdict == "allow":
                verdict, hit = "flag", r.id
        return verdict, hit
