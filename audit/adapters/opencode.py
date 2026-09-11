"""opencode adapter: scan the session store (~/.local/share/opencode/opencode.db, table `part`)
for tool outputs that contained a secret value. Read-only."""
import os
import sqlite3
import time

from .common import compile_pattern, redact

DEFAULT_DB = os.path.expanduser("~/.local/share/opencode/opencode.db")


def scan(db_path, secrets, days=0):
    """Yield hits {key, source, tool, session_id, ts, context}; returns (hits, parts_scanned)."""
    hits, scanned = [], 0
    if not db_path or not os.path.exists(db_path):
        return hits, scanned
    pattern = compile_pattern(secrets)
    if pattern is None:
        return hits, scanned
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        sql = ("SELECT session_id, time_created, json_extract(data, '$.tool'), "
               "json_extract(data, '$.state.output'), json_extract(data, '$.state.input.command'), "
               "json_extract(data, '$.state.input.filePath') FROM part WHERE data LIKE '%\"type\":\"tool\"%'")
        params = []
        if days and days > 0:
            sql += " AND time_created > ?"
            params.append(int((time.time() - days * 86400) * 1000))
        for session_id, time_created, tool, output, command, file_path in con.execute(sql, params):
            scanned += 1
            if not output:
                continue
            found = set(pattern.findall(output))
            if not found:
                continue
            # redact the whole context BEFORE truncating so a value straddling the cut
            # can never leave a partial fragment in the report
            context = redact(pattern, secrets, command or file_path or "")[:160]
            ts = (time_created or 0) / 1000.0
            for value in found:
                hits.append({"key": secrets[value], "source": "opencode", "tool": tool or "unknown",
                             "session_id": session_id, "ts": ts, "context": context})
    finally:
        con.close()
    return hits, scanned
