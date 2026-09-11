"""leak-audit against synthetic harness stores. The report must name keys, never values."""
import json
import sqlite3
import time

from audit import leak_audit
from audit.adapters.common import label_upstream
from guard.ledger import SCHEMA

SECRET = "zz-testsecret-0123456789abcdef"
OTHER = "zz-othersecret-fedcba9876543210"


def make_stores(tmp_path, upstream="https://openrouter.ai/api/v1"):
    env = tmp_path / ".env"
    env.write_text(f"LEAKED_KEY={SECRET}\nSAFE_KEY={OTHER}\n")

    oc = tmp_path / "opencode.db"
    con = sqlite3.connect(oc)
    con.execute("CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, session_id TEXT, time_created INTEGER, data TEXT)")
    t = int(time.time() * 1000) - 60_000
    tool_part = {"type": "tool", "tool": "bash",
                 "state": {"input": {"command": f"grep KEY .env   # {SECRET} pasted into the command too"},
                           "output": f"LEAKED_KEY={SECRET}\n"}}
    con.execute("INSERT INTO part VALUES (?,?,?,?,?)", ("p1", "m1", "ses_a", t, json.dumps(tool_part, separators=(",", ":"))))
    con.execute("INSERT INTO part VALUES (?,?,?,?,?)", ("p2", "m2", "ses_a", t + 1, json.dumps({"type": "text", "text": SECRET}, separators=(",", ":"))))
    con.commit(); con.close()

    ledger = tmp_path / "ledger.db"
    con = sqlite3.connect(ledger)
    con.executescript(SCHEMA)
    con.execute("INSERT INTO guard_tool_calls (ts, session_id, api_base, verdict) VALUES (?,?,?,?)",
                (t / 1000 + 2, "ses_a", upstream, "allow"))
    con.execute("INSERT INTO guard_masks (ts, session_id, key_name, n) VALUES (?,?,?,?)", (t / 1000 + 3, "ses_b", "SAFE_KEY", 4))
    con.commit(); con.close()

    cdir = tmp_path / "claude" / "-home-alice-proj"
    cdir.mkdir(parents=True)
    line = {"timestamp": "2026-09-01T10:00:00Z",
            "message": {"content": [{"type": "tool_result", "content": f"token: {SECRET}"}]}}
    (cdir / "s1.jsonl").write_text(json.dumps(line) + "\n" + json.dumps({"timestamp": "2026-09-01T10:00:01Z", "message": {"content": "plain"}}) + "\n")
    return env, oc, ledger, tmp_path / "claude"


def test_report_names_keys_and_upstream_without_values(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    env, oc, ledger, cdir = make_stores(tmp_path)
    report = leak_audit.run([str(env)], str(oc), str(cdir), str(ledger))
    dumped = json.dumps(report)
    assert SECRET not in dumped and OTHER not in dumped
    assert report["summary"] == {"secrets_with_hits": 1, "crossed_intermediary": 1}
    s = report["secrets"][0]
    assert s["key"] == "LEAKED_KEY" and s["total_hits"] == 2 and s["crossed_intermediary"]
    assert set(s["upstreams"]) == {"intermediary (openrouter.ai)", "first-party (api.anthropic.com)"}
    oc_example = next(e for e in s["examples"] if e["source"] == "opencode")
    assert "<LEAKED_KEY>" in oc_example["context"]       # redacted, not truncated into a fragment
    assert report["masked_by_guard"] == {"SAFE_KEY": 4}
    assert report["scanned"]["opencode_tool_parts"] == 1 and report["scanned"]["claude_jsonl_files"] == 1


def test_first_party_router_is_not_a_crossing(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    env, oc, ledger, cdir = make_stores(tmp_path, upstream="https://api.openai.com/v1")
    report = leak_audit.run([str(env)], str(oc), str(cdir), str(ledger))
    assert report["summary"]["crossed_intermediary"] == 0


def test_claude_code_behind_a_router(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://127.0.0.1:4000")
    env, oc, ledger, cdir = make_stores(tmp_path, upstream="https://api.openai.com/v1")
    report = leak_audit.run([str(env)], None, str(cdir), None)
    assert report["secrets"][0]["upstreams"] == {"intermediary (127.0.0.1:4000)": 1}


def test_missing_stores_and_no_router_rows(tmp_path):
    env, oc, ledger, cdir = make_stores(tmp_path)
    report = leak_audit.run([str(env)], str(oc), str(tmp_path / "nope"), str(tmp_path / "nope.db"))
    assert list(report["secrets"][0]["upstreams"]) == [leak_audit.router_log.NO_ROW]
    assert report["masked_by_guard"] == {}


def test_days_window(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    env, oc, ledger, cdir = make_stores(tmp_path)
    report = leak_audit.run([str(env)], str(oc), str(cdir), str(ledger), days=1)
    assert [h["source"] for s in report["secrets"] for h in s["examples"]] == ["opencode"]   # the 2026-09-01 transcript is older


def test_cli_exit_status_and_json(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    env, oc, ledger, cdir = make_stores(tmp_path)
    argv = ["--env", str(env), "--rules", str(tmp_path / "none.yaml"), "--opencode-db", str(oc),
            "--claude-dir", str(cdir), "--ledger-db", str(ledger), "--json"]
    try:
        leak_audit.main(argv)
    except SystemExit as e:
        assert e.code == 1
    out = capsys.readouterr().out
    assert SECRET not in out and json.loads(out)["summary"]["crossed_intermediary"] == 1


def test_label_upstream():
    assert label_upstream("https://api.anthropic.com/v1") == "first-party (api.anthropic.com)"
    assert label_upstream("https://some-reseller.example/v1") == "intermediary (some-reseller.example)"
    assert label_upstream("https://my-proxy.internal/v1", ("my-proxy.internal",)) == "first-party (my-proxy.internal)"
    assert label_upstream(None) == "unknown"
