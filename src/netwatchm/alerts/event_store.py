"""SQLite event store for persisting threat alerts with 72-hour retention."""
from __future__ import annotations

import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import Alert


def _default_db() -> str:
    if sys.platform == "win32":
        return str(Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "netwatchm" / "events.db")
    return "/var/lib/netwatchm/events.db"


DEFAULT_DB = _default_db()
RETENTION_HOURS = 360  # 15 days — uniform retention policy (was 72 = 3d pre-Session-29)

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   REAL    NOT NULL,
    alert_type  TEXT    NOT NULL,
    level       TEXT    NOT NULL,
    src_ip      TEXT,
    dst_ip      TEXT,
    description TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts    ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type  ON events (alert_type);
CREATE INDEX IF NOT EXISTS idx_events_level ON events (level);
"""


class EventStore:
    """Thread-safe SQLite-backed alert event store."""

    def __init__(self, db_path: str = DEFAULT_DB, retention_hours: int = RETENTION_HOURS) -> None:
        self.db_path = db_path
        self._retention_hours = retention_hours
        self._conn: sqlite3.Connection | None = None

    def open(self) -> "EventStore":
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_CREATE_SQL)
        self._conn.commit()
        return self

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "EventStore":
        return self.open()

    def __exit__(self, *_: object) -> None:
        self.close()

    def insert(self, alert: "Alert") -> None:
        """Insert alert and prune events older than retention window."""
        assert self._conn, "EventStore not open"
        cutoff = time.time() - self._retention_hours * 3600
        self._conn.execute(
            "INSERT INTO events (timestamp, alert_type, level, src_ip, dst_ip, description) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                alert.timestamp.timestamp(),
                alert.alert_type,
                str(alert.level),
                alert.src_ip,
                alert.dst_ip,
                alert.description,
            ),
        )
        self._conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        self._conn.commit()

    def query(
        self,
        limit: int = 200,
        alert_type: str | None = None,
        level: str | None = None,
        ip: str | None = None,
    ) -> list[dict]:
        """Return events newest-first, optionally filtered."""
        assert self._conn, "EventStore not open"
        clauses: list[str] = []
        params: list = []
        if alert_type:
            clauses.append("alert_type = ?")
            params.append(alert_type)
        if level:
            clauses.append("level = ?")
            params.append(level.upper())
        if ip:
            clauses.append("(src_ip = ? OR dst_ip = ?)")
            params.extend([ip, ip])
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        cur = self._conn.execute(
            f"SELECT id, timestamp, alert_type, level, src_ip, dst_ip, description "
            f"FROM events {where} ORDER BY timestamp DESC LIMIT ?",
            params,
        )
        return [dict(r) for r in cur.fetchall()]

    def distinct_types(self) -> list[str]:
        """Return sorted list of distinct alert_type values."""
        assert self._conn, "EventStore not open"
        cur = self._conn.execute(
            "SELECT DISTINCT alert_type FROM events ORDER BY alert_type"
        )
        return [r[0] for r in cur.fetchall()]

    def count(self) -> int:
        """Return total number of stored events."""
        assert self._conn, "EventStore not open"
        cur = self._conn.execute("SELECT COUNT(*) FROM events")
        return cur.fetchone()[0]
