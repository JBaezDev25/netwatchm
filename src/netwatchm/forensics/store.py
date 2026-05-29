"""SQLite store for incident cases opened by the ForensicHandler.

One row per *correlated* incident: the triggering alert, the captured pcap
path, the threat-intel verdict, a mutable triage state (priority + assignee +
review status), and a ``hits`` counter that grows when the same alert type
from the same IP recurs inside the correlation window. Mirrors the lightweight
open()/insert() pattern of ``alerts/event_store.py``.
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

PRIORITY_LOW = "low"
PRIORITY_MEDIUM = "medium"
PRIORITY_HIGH = "high"
PRIORITY_CRITICAL = "critical"
_VALID_PRIORITY = {PRIORITY_LOW, PRIORITY_MEDIUM, PRIORITY_HIGH, PRIORITY_CRITICAL}

# Initial triage priority derived from the alert ThreatLevel name.
_LEVEL_PRIORITY = {
    "LOW": PRIORITY_LOW,
    "MEDIUM": PRIORITY_MEDIUM,
    "HIGH": PRIORITY_HIGH,
    "CRITICAL": PRIORITY_CRITICAL,
}

# Group repeat alerts (same type + same external IP) into one open case if
# they recur within this window, instead of creating a duplicate row.
DEFAULT_CORRELATION_SECONDS = 3600


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
    priority: str = ""          # blank → derived from level at insert
    assignee: str = ""


class IncidentStore:
    def __init__(self, db_path: str = DEFAULT_DB, retention_days: int = 15,
                 correlation_seconds: int = DEFAULT_CORRELATION_SECONDS) -> None:
        self._path = db_path
        self._retention_seconds = retention_days * 86400
        self._correlation_seconds = correlation_seconds
        self._conn: sqlite3.Connection | None = None

    def open(self) -> "IncidentStore":
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at   REAL    NOT NULL,
                last_seen    REAL    NOT NULL DEFAULT 0,
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
                status       TEXT    DEFAULT 'open',
                priority     TEXT    DEFAULT 'medium',
                assignee     TEXT    DEFAULT '',
                hits         INTEGER DEFAULT 1
            )
            """
        )
        self._migrate()
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at)"
        )
        self._conn.commit()
        return self

    def _migrate(self) -> None:
        """Add triage columns to a pre-Session-33 table that lacks them."""
        assert self._conn is not None
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(incidents)")}
        adds = {
            "last_seen": "REAL DEFAULT 0",
            "priority": "TEXT DEFAULT 'medium'",
            "assignee": "TEXT DEFAULT ''",
            "hits": "INTEGER DEFAULT 1",
        }
        for name, decl in adds.items():
            if name not in cols:
                self._conn.execute(f"ALTER TABLE incidents ADD COLUMN {name} {decl}")

    def insert(self, incident: Incident) -> int:
        """Insert a new case, or correlate into a recent open one.

        If an *open* incident with the same alert_type + src_ip + dst_ip exists
        within the correlation window, its ``hits`` counter is bumped and
        ``last_seen``/description refreshed; the existing id is returned and no
        new row is created.
        """
        assert self._conn is not None, "store not opened"
        now = incident.created_at

        existing = self._find_correlated(incident, now)
        if existing is not None:
            self._conn.execute(
                "UPDATE incidents SET hits = hits + 1, last_seen=?, description=? "
                "WHERE id=?",
                (now, incident.description, existing),
            )
            self._conn.commit()
            return existing

        priority = incident.priority or _LEVEL_PRIORITY.get(
            incident.level.upper(), PRIORITY_MEDIUM
        )
        cur = self._conn.execute(
            """
            INSERT INTO incidents
                (created_at, last_seen, alert_type, level, src_ip, dst_ip, description,
                 verdict, score, intel_summary, intel_json, pcap_path, pcap_bytes,
                 status, priority, assignee, hits)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
            """,
            (
                incident.created_at, now, incident.alert_type, incident.level,
                incident.src_ip, incident.dst_ip, incident.description,
                incident.verdict, incident.score, incident.intel_summary,
                incident.intel_json, incident.pcap_path, incident.pcap_bytes,
                incident.status, priority, incident.assignee,
            ),
        )
        self._conn.commit()
        self._prune()
        return int(cur.lastrowid)

    def _find_correlated(self, incident: Incident, now: float) -> int | None:
        assert self._conn is not None
        cutoff = now - self._correlation_seconds
        row = self._conn.execute(
            """SELECT id FROM incidents
               WHERE alert_type=? AND src_ip=? AND dst_ip=? AND status=?
                 AND last_seen >= ?
               ORDER BY last_seen DESC LIMIT 1""",
            (incident.alert_type, incident.src_ip, incident.dst_ip,
             STATUS_OPEN, cutoff),
        ).fetchone()
        return int(row["id"]) if row else None

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

    def set_priority(self, incident_id: int, priority: str) -> bool:
        if priority not in _VALID_PRIORITY:
            return False
        assert self._conn is not None, "store not opened"
        self._conn.execute(
            "UPDATE incidents SET priority=? WHERE id=?", (priority, incident_id)
        )
        self._conn.commit()
        return True

    def set_assignee(self, incident_id: int, assignee: str) -> bool:
        assert self._conn is not None, "store not opened"
        self._conn.execute(
            "UPDATE incidents SET assignee=? WHERE id=?", (assignee.strip(), incident_id)
        )
        self._conn.commit()
        return True

    def query(self, *, limit: int = 200, status: str | None = None,
              ip: str | None = None, priority: str | None = None,
              assignee: str | None = None) -> list[dict]:
        assert self._conn is not None, "store not opened"
        sql = "SELECT * FROM incidents"
        clauses, params = [], []
        if status:
            clauses.append("status=?")
            params.append(status)
        if priority:
            clauses.append("priority=?")
            params.append(priority)
        if assignee:
            clauses.append("assignee=?")
            params.append(assignee)
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
