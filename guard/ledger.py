"""Append-only ledger (sqlite): which tool calls came back, from which upstream, with what verdict;
which secret NAMES were masked outbound. Values never touch this file."""
import hashlib
import json
import os
import sqlite3
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB_PATH = os.path.expanduser(os.environ.get("LLM_GUARD_DB") or os.path.join(REPO, "guard-ledger.db"))
DB_PATH = DEFAULT_DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS guard_tool_calls (
  id INTEGER PRIMARY KEY,
  ts REAL NOT NULL,
  session_id TEXT,
  requested_model TEXT,
  model TEXT,
  api_base TEXT,
  model_id TEXT,
  stream INTEGER,
  tool_name TEXT,
  args_sha256 TEXT,
  args_prefix TEXT,
  verdict TEXT NOT NULL,
  rule TEXT
);
CREATE INDEX IF NOT EXISTS guard_tool_calls_ts ON guard_tool_calls(ts);
CREATE INDEX IF NOT EXISTS guard_tool_calls_verdict ON guard_tool_calls(verdict, ts);
CREATE INDEX IF NOT EXISTS guard_tool_calls_session ON guard_tool_calls(session_id, ts);
CREATE TABLE IF NOT EXISTS guard_masks (
  id INTEGER PRIMARY KEY,
  ts REAL NOT NULL,
  session_id TEXT,
  requested_model TEXT,
  key_name TEXT NOT NULL,
  n INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS guard_masks_ts ON guard_masks(ts);
"""

_lock = threading.Lock()
_conn = None


def configure(path):
    """Point the ledger at `path` (None keeps the current one). Safe to call before any write."""
    global DB_PATH, _conn
    if not path:
        return
    path = os.path.expanduser(path)
    with _lock:
        if path != DB_PATH and _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
            _conn = None
        DB_PATH = path


def _db():
    global _conn
    if _conn is None:
        c = sqlite3.connect(DB_PATH, timeout=5, check_same_thread=False)
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
        _conn = c
    return _conn


def tool_call(ctx, tool_name, arguments, verdict, rule):
    try:
        args = arguments if isinstance(arguments, str) else json.dumps(arguments or {})
        row = (time.time(), ctx.get("session_id"), ctx.get("requested_model"), ctx.get("model"),
               ctx.get("api_base"), ctx.get("model_id"), 1 if ctx.get("stream") else 0,
               tool_name, hashlib.sha256(args.encode("utf-8", "replace")).hexdigest(),
               args[:200], verdict, rule)
        with _lock:
            _db().execute("INSERT INTO guard_tool_calls (ts, session_id, requested_model, model, api_base, "
                          "model_id, stream, tool_name, args_sha256, args_prefix, verdict, rule) "
                          "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", row)
            _db().commit()
    except Exception:
        pass


def masks(ctx, counts):
    if not counts:
        return
    try:
        now = time.time()
        with _lock:
            _db().executemany("INSERT INTO guard_masks (ts, session_id, requested_model, key_name, n) VALUES (?,?,?,?,?)",
                              [(now, ctx.get("session_id"), ctx.get("requested_model"), k, n) for k, n in counts.items()])
            _db().commit()
    except Exception:
        pass
