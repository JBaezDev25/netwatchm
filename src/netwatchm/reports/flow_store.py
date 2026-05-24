"""SQLite flow store with 72-hour rolling retention."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .connection_report import FlowRecord

DEFAULT_DB = "/var/lib/netwatchm/flows.db"

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS flows (
    id          INTEGER PRIMARY KEY,
    captured_at TEXT    NOT NULL,
    src_ip      TEXT,
    src_host    TEXT,
    dst_ip      TEXT,
    dst_port    INTEGER,
    protocol    TEXT,
    domain      TEXT,
    app_name    TEXT,
    username    TEXT,
    packets     INTEGER,
    bytes       INTEGER,
    first_seen  REAL,
    last_seen   REAL
);
CREATE INDEX IF NOT EXISTS idx_captured_at ON flows (captured_at);
CREATE INDEX IF NOT EXISTS idx_src_ip      ON flows (src_ip);
CREATE INDEX IF NOT EXISTS idx_dst_ip      ON flows (dst_ip);
"""

_RETENTION_HOURS = 360  # 15 days — Session 29 uniform retention (was 72 = 3d)


class FlowStore:
    """Thread-safe SQLite-backed flow store."""

    def __init__(self, db_path: str = DEFAULT_DB) -> None:
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------
    # Context manager / lifecycle
    # ------------------------------------------------------------------

    def open(self) -> "FlowStore":
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

    def __enter__(self) -> "FlowStore":
        return self.open()

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def insert_flows(self, flows: list[FlowRecord]) -> None:
        """Batch-insert flows and purge records older than 72 hours."""
        assert self._conn, "FlowStore not open"
        now = datetime.now(timezone.utc).isoformat()
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=_RETENTION_HOURS)).isoformat()

        self._conn.executemany(
            """
            INSERT INTO flows
                (captured_at, src_ip, src_host, dst_ip, dst_port,
                 protocol, domain, app_name, username, packets, bytes,
                 first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    now,
                    f.src_ip,
                    f.src_hostname,
                    f.dst_ip,
                    f.dst_port,
                    f.protocol,
                    f.domain if f.domain != "—" else None,
                    f.app_name,
                    f.username,
                    f.packet_count,
                    f.bytes_total,
                    f.first_seen,
                    f.last_seen,
                )
                for f in flows
            ],
        )
        self._conn.execute("DELETE FROM flows WHERE captured_at < ?", (cutoff,))
        self._conn.commit()

    # ------------------------------------------------------------------
    # Read / Analytics queries
    # ------------------------------------------------------------------

    def query_analytics(self) -> dict:
        """Return all analytics data as a dict ready for the HTML renderer."""
        assert self._conn, "FlowStore not open"
        cur = self._conn.cursor()

        # -- Totals --
        cur.execute("SELECT COUNT(*), COALESCE(SUM(bytes),0), COALESCE(SUM(packets),0) FROM flows")
        row = cur.fetchone()
        totals = {"flows": row[0], "bytes": row[1], "packets": row[2]}

        # -- Bytes per device (top 20) --
        cur.execute("""
            SELECT src_ip,
                   MAX(src_host) AS src_host,
                   COALESCE(SUM(bytes), 0) AS total_bytes
            FROM flows
            GROUP BY src_ip
            ORDER BY total_bytes DESC
            LIMIT 20
        """)
        devices = [
            {"ip": r["src_ip"], "host": r["src_host"] or r["src_ip"], "bytes": r["total_bytes"]}
            for r in cur.fetchall()
        ]

        # -- Top 10 destinations --
        cur.execute("""
            SELECT dst_ip,
                   MAX(domain) AS domain,
                   dst_port,
                   COALESCE(SUM(bytes), 0) AS total_bytes
            FROM flows
            GROUP BY dst_ip
            ORDER BY total_bytes DESC
            LIMIT 10
        """)
        top_dst = [
            {
                "ip": r["dst_ip"],
                "domain": r["domain"] or r["dst_ip"],
                "port": r["dst_port"],
                "bytes": r["total_bytes"],
            }
            for r in cur.fetchall()
        ]

        # -- Protocol breakdown --
        cur.execute("""
            SELECT COALESCE(protocol, 'Other') AS proto,
                   COALESCE(SUM(bytes), 0) AS total_bytes
            FROM flows
            GROUP BY proto
            ORDER BY total_bytes DESC
        """)
        protocols = [{"name": r["proto"], "bytes": r["total_bytes"]} for r in cur.fetchall()]

        # -- Hourly activity (last 72 h, UTC) --
        cur.execute("""
            SELECT strftime('%Y-%m-%dT%H:00', captured_at) AS hour,
                   COALESCE(SUM(bytes), 0) AS total_bytes
            FROM flows
            GROUP BY hour
            ORDER BY hour
        """)
        hourly = [{"hour": r["hour"], "bytes": r["total_bytes"]} for r in cur.fetchall()]

        # -- Per-device drill-down (top 10 devices, top 5 flows each) --
        device_details: list[dict] = []
        for dev in devices[:10]:
            cur.execute(
                """
                SELECT dst_ip,
                       MAX(domain) AS domain,
                       protocol,
                       COALESCE(SUM(bytes), 0) AS total_bytes,
                       MAX(captured_at) AS last_seen
                FROM flows
                WHERE src_ip = ?
                GROUP BY dst_ip, protocol
                ORDER BY total_bytes DESC
                LIMIT 5
                """,
                (dev["ip"],),
            )
            dev_flows = [
                {
                    "dst": r["dst_ip"],
                    "domain": r["domain"] or r["dst_ip"],
                    "proto": r["protocol"] or "—",
                    "bytes": r["total_bytes"],
                    "last": r["last_seen"],
                }
                for r in cur.fetchall()
            ]
            device_details.append({"device": dev, "flows": dev_flows})

        return {
            "totals": totals,
            "devices": devices,
            "top_destinations": top_dst,
            "protocols": protocols,
            "hourly": hourly,
            "device_details": device_details,
        }
