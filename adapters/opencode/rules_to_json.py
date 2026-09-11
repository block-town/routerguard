#!/usr/bin/env python3
"""Convert the guard rules file to the JSON the opencode plugin reads, so both enforcement
points share one ruleset. Special patterns (__SECRET_VALUE__) are dropped: the plugin has
no secret list.

    python adapters/opencode/rules_to_json.py rules.yaml > ~/.config/opencode/guard-rules.json
"""
import json
import re
import sys

import yaml


def convert(path):
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}
    out = []
    for r in cfg.get("rules", []):
        pat = r["pattern"]
        if pat.startswith("__"):
            continue
        re.compile(pat)  # fail loudly on a bad pattern
        out.append({"id": r["id"], "action": r.get("action", "flag"), "pattern": pat})
    return {"rules": out}


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "rules.yaml"
    print(json.dumps(convert(src), indent=2))
