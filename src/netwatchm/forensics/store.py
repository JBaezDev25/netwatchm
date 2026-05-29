"""SQLite store for incident cases opened by the ForensicHandler.

One row per incident: the triggering alert, the captured pcap path, the
threat-intel verdict, and a mutable review status (open/reviewed/false_positive).
Mirrors the lightweight open()/insert() pattern of ``alerts/event_store.py``.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field

log = logging.getLogger("netwatchm.forensics")

DEFAULT_DB = "/var/lib/netwatchm/forensics.db"

STATUS_OPEN = "open"
STATUS_REVIEWED = "reviewed"
STATUS_FALSE_POSITIVE = "false_positive"
_VALID_STATUS = {STATUS_OPEN, STATUS_REVIEWED, STATUS_FALSE_POSITIVE}


@dataclass
class Incident:
    alert_type: str
    level: str
    src_ip: str
    dst_ip: str
    description: str
    created_at: float = field(default_factory=time.time)
    verdict: str = "unknown"
    score: int = 0
    intel_summary: str = ""
    intel_json: str = "{}"
    pcap_path: str = ""
    pcap_bytes: int = 0
    status: str = STATUS_OPEN


class IncidentStore:
    def __init__(self, db_path: str = DEFAULT_DB, retention_days: int = 15) -> None:
        self._path = db_path
        self._retention_seconds = retention_days * 86400
        self._conn: sqlite3.Connection | None = None

    def open(self) -> "IncidentStore":
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at   REAL    NOT NULL,
                alert_type   TEXT    NOT NULL,
                level        TEXT    NOT NULL,
                src_ip       TEXT,
                dst_ip       TEXT,
                description  TEXT,
                verdict      TEXT    DEFAULT 'unknown',
                score        INTEGER DEFAULT 0,
                intel_summary TEXT,
                intel_json   TEXT    DEFAULT '{}',
                pcap_path    TEXT    DEFAULT '',
                pcap_bytes   INTEGER DEFAULT 0,
                status       TEXT    DEFAULT 'open'
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at)"
        )
        self._conn.commit()
        return self

    def insert(self, incident: Incident) -> int:
        assert self._conn is not None, "store not opened"
        cur = self._conn.execute(
            """
            INSERT INTO incidents
                (created_at, alert_type, level, src_ip, dst_ip, description,
                 verdict, score, intel_summary, intel_json, pcap_path, pcap_bytes, status)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                incident.created_at, incident.alert_type, incident.level,
                incident.src_ip, incident.dst_ip, incident.description,
                incident.verdict, incident.score, incident.intel_summary,
                incident.intel_json, incident.pcap_path, incident.pcap_bytes,
                incident.status,
            ),
        )
        self._conn.commit()
        self._prune()
        return int(cur.lastrowid)

    def update_artifacts(self, incident_id: int, *, verdict: str, score: int,
                         intel_summary: str, intel_json: str,
                         pcap_path: str, pcap_bytes: int) -> None:
        assert self._conn is not None, "store not opened"
        self._conn.execute(
            """UPDATE incidents SET verdict=?, score=?, intel_summary=?,
               intel_json=?, pcap_path=?, pcap_bytes=? WHERE id=?""",
            (verdict, score, intel_summary, intel_json, pcap_path, pcap_bytes, incident_id),
        )
        self._conn.commit()

    def set_status(self, incident_id: int, status: str) -> bool:
        if status not in _VALID_STATUS:
            return False
        assert self._conn is not None, "store not opened"
        self._conn.execute(
            "UPDATE incidents SET status=? WHERE id=?", (status, incident_id)
        )
        self._conn.commit()
        return True

    def query(self, *, limit: int = 200, status: str | None = None,
              ip: str | None = None) -> list[dict]:
        assert self._conn is not None, "store not opened"
        sql = "SELECT * FROM incidents"
        clauses, params = [], []
        if status:
            clauses.append("status=?")
            params.append(status)
        if ip:
            clauses.append("(src_ip=? OR dst_ip=?)")
            params.extend([ip, ip])
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get(self, incident_id: int) -> dict | None:
        assert self._conn is not None, "store not opened"
        row = self._conn.execute(
            "SELECT * FROM incidents WHERE id=?", (incident_id,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def _row_to_dict(self, row: sqlite3.Row) -> dict:
        d = dict(row)
        try:
            d["intel"] = json.loads(d.pop("intel_json", "{}") or "{}")
        except (json.JSONDecodeError, TypeError):
            d["intel"] = {}
        return d

    def _prune(self) -> None:
        assert self._conn is not None
        cutoff = time.time() - self._retention_seconds
        self._conn.execute("DELETE FROM incidents WHERE created_at < ?", (cutoff,))
        self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
