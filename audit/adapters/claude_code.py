"""Claude Code adapter: scan ~/.claude/projects/**/*.jsonl transcripts for tool_result blocks that
contained a secret value. Read-only. Claude Code talks to Anthropic directly unless
ANTHROPIC_BASE_URL points it at a router, so the upstream label comes from that variable."""
import json
import os
import time
from datetime import datetime

from .common import label_upstream

DEFAULT_DIR = os.path.expanduser("~/.claude/projects")


def _parse_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def _has_tool_result(obj):
    if isinstance(obj, dict):
        if obj.get("type") == "tool_result":
            return True
        return any(_has_tool_result(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_tool_result(v) for v in obj)
    return False


def upstream_label(extra_first_party=()):
    base = os.environ.get("ANTHROPIC_BASE_URL")
    if not base:
        return "first-party (api.anthropic.com)"
    return label_upstream(base, extra_first_party)


def scan(claude_dir, secrets, days=0, extra_first_party=()):
    """Returns (hits, files_scanned). Hits: {key, source, tool, file, line_no, ts, upstream}."""
    hits, scanned = [], 0
    if not claude_dir or not os.path.isdir(claude_dir):
        return hits, scanned
    values = list(secrets)
    if not values:
        return hits, scanned
    cutoff = (time.time() - days * 86400) if (days and days > 0) else None
    label = upstream_label(extra_first_party)
    for root, dirs, files in os.walk(claude_dir):
        if "/memory/" in root + "/":
            dirs[:] = []
            continue
        for fn in files:
            if not fn.endswith(".jsonl"):
                continue
            full = os.path.join(root, fn)
            scanned += 1
            rel = os.path.relpath(full, claude_dir)
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    for line_no, line in enumerate(fh, start=1):
                        matched = [v for v in values if v in line]
                        if not matched:
                            continue
                        try:
                            d = json.loads(line)
                        except Exception:
                            continue
                        if not _has_tool_result(d):
                            continue
                        ts = _parse_ts(d.get("timestamp"))
                        if cutoff is not None and ts is not None and ts < cutoff:
                            continue
                        for v in matched:
                            hits.append({"key": secrets[v], "source": "claude-code", "tool": "tool_result",
                                         "file": rel, "line_no": line_no, "ts": ts or 0.0, "upstream": label})
            except OSError:
                continue
    return hits, scanned
