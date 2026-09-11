#!/usr/bin/env python3
"""leak-audit: retroactive secret-leak audit.

Answers: which of my secrets have ever appeared in a tool result that was sent back to a
model (opencode session store, Claude Code transcripts), and which upstream served the very
next request in that session?

Reads secret VALUES only from local KEY=value files to build a value -> NAME map, then greps
read-only copies of the harness stores for those values. NEVER prints a value, only the key
name that owns it. Read-only against every data source.

    python -m audit.leak_audit --env ~/.env --env ~/work/app/.env
    python -m audit.leak_audit --days 30 --json

Exit status 1 when at least one secret crossed an intermediary, 0 otherwise.
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime

from .adapters import claude_code, opencode, router_log
from .adapters.common import is_intermediary, load_env_file


def _rules_secret_files(rules_path):
    """secret_files from the guard rules file, if pyyaml and the file are available."""
    try:
        import yaml
        with open(os.path.expanduser(rules_path)) as f:
            cfg = yaml.safe_load(f) or {}
        return list(cfg.get("secret_files") or [])
    except Exception:
        return []


def default_rules_path():
    try:
        from guard.gate import default_rules_path as p
        return p()
    except Exception:
        return None


def default_ledger_db():
    try:
        from guard.ledger import DEFAULT_DB_PATH
        return DEFAULT_DB_PATH
    except Exception:
        return None


def fmt_local(ts):
    if not ts:
        return "unknown"
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "unknown"


def build_report(all_hits, scan_meta, masked):
    by_key = {}
    for h in all_hits:
        by_key.setdefault(h["key"], []).append(h)
    summaries = []
    for key, hits in by_key.items():
        hits_sorted = sorted(hits, key=lambda h: h["ts"])
        upstreams = {}
        for h in hits:
            upstreams[h["upstream"]] = upstreams.get(h["upstream"], 0) + 1
        examples = []
        for h in hits_sorted[:5]:
            ctx = f"{h['file']}:{h['line_no']}" if h["source"] == "claude-code" else h.get("context", "")
            examples.append({"source": h["source"], "tool": h["tool"], "date": fmt_local(h["ts"]), "context": ctx})
        summaries.append({
            "key": key,
            "total_hits": len(hits),
            "first_seen": fmt_local(hits_sorted[0]["ts"]),
            "last_seen": fmt_local(hits_sorted[-1]["ts"]),
            "upstreams": upstreams,
            "crossed_intermediary": any(is_intermediary(u) for u in upstreams),
            "examples": examples,
        })
    summaries.sort(key=lambda s: s["total_hits"], reverse=True)
    return {
        "scanned": scan_meta,
        "secrets": summaries,
        "masked_by_guard": masked,
        "summary": {
            "secrets_with_hits": len(summaries),
            "crossed_intermediary": sum(1 for s in summaries if s["crossed_intermediary"]),
        },
    }


def print_human(report):
    m = report["scanned"]
    print(f"leak-audit: {m['env_files']} env file(s), {m['secret_names']} secret name(s) loaded")
    print(f"opencode: scanned {m['opencode_tool_parts']} tool part(s)")
    print(f"claude-code: scanned {m['claude_jsonl_files']} transcript file(s)")
    print(f"window: last {m['days']} day(s)" if m["days"] else "window: all time")
    print(f"elapsed: {m['elapsed_seconds']:.2f}s")
    print()
    for s in report["secrets"]:
        print(s["key"])
        print(f"  total hits: {s['total_hits']}")
        print(f"  first seen: {s['first_seen']}    last seen: {s['last_seen']}")
        for upstream, n in sorted(s["upstreams"].items(), key=lambda kv: -kv[1]):
            print(f"  {upstream}: {n}")
        for ex in s["examples"]:
            print(f"  {ex['source']}/{ex['tool']} | {ex['date']} | {ex['context']}")
        print()
    if report["masked_by_guard"]:
        print("masked outbound by the guard since it was installed:")
        for k, n in sorted(report["masked_by_guard"].items(), key=lambda kv: -kv[1]):
            print(f"  {k}: {n}")
        print()
    n, c = report["summary"]["secrets_with_hits"], report["summary"]["crossed_intermediary"]
    print(f"{n} secret(s) appeared in tool output; {c} of them crossed an intermediary.")


def run(env_paths, opencode_db=None, claude_dir=None, ledger_db=None, router_table="guard_tool_calls",
        days=0, extra_first_party=()):
    t0 = time.monotonic()
    secrets, names, files_found = {}, [], 0
    for p in env_paths:
        if load_env_file(p, secrets, names):
            files_found += 1
    oc_hits, oc_parts = opencode.scan(opencode_db, secrets, days)
    router_log.attach_upstreams(oc_hits, ledger_db, router_table, extra_first_party)
    cc_hits, cc_files = claude_code.scan(claude_dir, secrets, days, extra_first_party)
    meta = {"env_files": files_found, "secret_names": len(set(names)), "opencode_tool_parts": oc_parts,
            "claude_jsonl_files": cc_files, "days": days, "elapsed_seconds": time.monotonic() - t0}
    return build_report(oc_hits + cc_hits, meta, router_log.masked_counts(ledger_db))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="leak-audit", description=__doc__.split("\n\n")[1])
    ap.add_argument("--env", action="append", default=[], help="KEY=value file to take secret values from (repeatable)")
    ap.add_argument("--rules", default=default_rules_path(), help="guard rules file whose secret_files are also used")
    ap.add_argument("--opencode-db", default=opencode.DEFAULT_DB)
    ap.add_argument("--claude-dir", default=claude_code.DEFAULT_DIR)
    ap.add_argument("--ledger-db", default=default_ledger_db(), help="sqlite file with the router log")
    ap.add_argument("--router-table", default="guard_tool_calls", help="table with session_id, ts, api_base")
    ap.add_argument("--first-party", action="append", default=[], help="extra host substring to treat as first-party")
    ap.add_argument("--days", type=int, default=0, help="0 = all time (default)")
    ap.add_argument("--json", action="store_true", dest="as_json")
    a = ap.parse_args(argv)

    env_paths = list(a.env)
    if a.rules:
        env_paths += _rules_secret_files(a.rules)
    env_paths += [p for p in os.environ.get("LLM_GUARD_SECRET_FILES", "").split(":") if p]
    if not env_paths:
        ap.error("no secret files: pass --env, set secret_files in the rules file, or LLM_GUARD_SECRET_FILES")

    report = run(env_paths, a.opencode_db, a.claude_dir, a.ledger_db, a.router_table, a.days, tuple(a.first_party))
    if a.as_json:
        print(json.dumps(report, indent=2))
    else:
        print_human(report)
    sys.exit(1 if report["summary"]["crossed_intermediary"] > 0 else 0)


if __name__ == "__main__":
    main()
