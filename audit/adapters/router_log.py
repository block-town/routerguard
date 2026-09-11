"""Router-log adapter: for each hit, which upstream served the NEXT request in that session?

Reads the guard ledger (table guard_tool_calls: session_id, ts, api_base) by default. Any
table with those three columns works: pass --router-table. Also reports what the guard's
outbound masker already caught (table guard_masks)."""
import os
import sqlite3

from .common import label_upstream

NO_ROW = "no router row (direct provider, or before logging started)"


def _table_exists(con, name):
    row = con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    return row is not None


def attach_upstreams(hits, db_path, table="guard_tool_calls", extra_first_party=()):
    """Set hit['upstream'] for hits that carry a session_id and no label yet."""
    todo = [h for h in hits if "upstream" not in h]
    if not todo:
        return
    if not db_path or not os.path.exists(db_path):
        for h in todo:
            h["upstream"] = NO_ROW
        return
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        if not _table_exists(con, table):
            for h in todo:
                h["upstream"] = NO_ROW
            return
        q = f"SELECT api_base FROM {table} WHERE session_id=? AND ts>=? ORDER BY ts LIMIT 1"  # table name validated above
        for h in todo:
            row = con.execute(q, (h.get("session_id"), h["ts"] - 1)).fetchone() if h.get("session_id") else None
            h["upstream"] = label_upstream(row[0], extra_first_party) if row and row[0] else NO_ROW
    finally:
        con.close()


def masked_counts(db_path):
    """{key_name: occurrences masked outbound} from guard_masks, or {} if absent."""
    if not db_path or not os.path.exists(db_path):
        return {}
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        if not _table_exists(con, "guard_masks"):
            return {}
        return {k: n for k, n in con.execute("SELECT key_name, SUM(n) FROM guard_masks GROUP BY key_name")}
    finally:
        con.close()
