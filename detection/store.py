"""
Alert persistence for Sentinel-E.

Every raised alert is written to two places:
  * a JSON-lines file (human-greppable, easy to replay/diff), and
  * a SQLite database (queryable history that survives restarts).

On startup the dashboard loads recent history from SQLite so a reconnecting
analyst still sees the alerts that fired while the browser was closed.
"""
import json
import os
import sqlite3


class AlertStore:
    def __init__(self, jsonl_path, db_path):
        self.jsonl_path = jsonl_path
        self.db_path = db_path
        for p in (jsonl_path, db_path):
            os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ts            TEXT,
                stage         TEXT,
                stage_num     INTEGER,
                stage_name    TEXT,
                technique_id  TEXT,
                technique_name TEXT,
                phase         TEXT,
                severity      TEXT,
                src_ip        TEXT,
                description   TEXT,
                detail        TEXT
            )""")
        self._db.commit()

    def save(self, alert):
        # JSON-lines sink
        with open(self.jsonl_path, "a") as f:
            f.write(json.dumps(alert) + "\n")
        # SQLite sink
        self._db.execute(
            """INSERT INTO alerts (ts,stage,stage_num,stage_name,technique_id,
                 technique_name,phase,severity,src_ip,description,detail)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (alert["ts"], alert["stage"], alert["stage_num"], alert["stage_name"],
             alert["technique_id"], alert["technique_name"], alert["phase"],
             alert["severity"], alert["src_ip"], alert["description"],
             json.dumps(alert.get("detail", {}))))
        self._db.commit()

    def recent(self, limit=200):
        cur = self._db.execute(
            "SELECT ts,stage,stage_num,stage_name,technique_id,technique_name,"
            "phase,severity,src_ip,description,detail FROM alerts "
            "ORDER BY id DESC LIMIT ?", (limit,))
        cols = [c[0] for c in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        for r in rows:
            try:
                r["detail"] = json.loads(r["detail"])
            except (ValueError, TypeError):
                r["detail"] = {}
        return list(reversed(rows))  # oldest-first for replay into the feed
