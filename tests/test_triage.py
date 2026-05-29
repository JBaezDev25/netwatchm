"""Tests for incident triage: priority, assignee, correlation/dedup, migration."""
from __future__ import annotations

import sqlite3
import time

from netwatchm.forensics.store import (
    PRIORITY_CRITICAL,
    PRIORITY_HIGH,
    STATUS_FALSE_POSITIVE,
    Incident,
    IncidentStore,
)


def _inc(alert_type="PORT_SCAN", level="HIGH", src="203.0.113.5",
         dst="192.168.1.10", description="x", **kw) -> Incident:
    return Incident(alert_type=alert_type, level=level, src_ip=src, dst_ip=dst,
                    description=description, **kw)


def test_priority_derived_from_level(tmp_path):
    store = IncidentStore(str(tmp_path / "f.db")).open()
    iid = store.insert(_inc(level="CRITICAL"))
    assert store.get(iid)["priority"] == PRIORITY_CRITICAL


def test_explicit_priority_wins(tmp_path):
    store = IncidentStore(str(tmp_path / "f.db")).open()
    iid = store.insert(_inc(level="LOW", priority=PRIORITY_HIGH))
    assert store.get(iid)["priority"] == PRIORITY_HIGH


def test_set_priority_and_assignee(tmp_path):
    store = IncidentStore(str(tmp_path / "f.db")).open()
    iid = store.insert(_inc())
    assert store.set_priority(iid, "critical") is True
    assert store.set_priority(iid, "bogus") is False
    assert store.set_assignee(iid, "  alice ") is True
    row = store.get(iid)
    assert row["priority"] == "critical"
    assert row["assignee"] == "alice"


def test_correlation_dedups_same_type_and_ip(tmp_path):
    store = IncidentStore(str(tmp_path / "f.db"), correlation_seconds=3600).open()
    a = store.insert(_inc())
    b = store.insert(_inc(description="again"))
    assert a == b
    row = store.get(a)
    assert row["hits"] == 2
    assert row["description"] == "again"


def test_correlation_new_row_outside_window(tmp_path):
    store = IncidentStore(str(tmp_path / "f.db"), correlation_seconds=60).open()
    now = time.time()
    a = store.insert(_inc(created_at=now - 1000))
    b = store.insert(_inc(created_at=now))
    assert a != b


def test_correlation_does_not_merge_reviewed(tmp_path):
    store = IncidentStore(str(tmp_path / "f.db")).open()
    a = store.insert(_inc())
    store.set_status(a, STATUS_FALSE_POSITIVE)
    b = store.insert(_inc())  # prior case is closed → new case opens
    assert a != b


def test_query_filters_priority_and_assignee(tmp_path):
    store = IncidentStore(str(tmp_path / "f.db")).open()
    i1 = store.insert(_inc(src="1.1.1.1", dst="10.0.0.1"))
    store.insert(_inc(src="2.2.2.2", dst="10.0.0.2", level="LOW"))
    store.set_assignee(i1, "bob")
    assert len(store.query(priority="high")) == 1
    assert len(store.query(assignee="bob")) == 1


def test_migration_adds_columns_to_legacy_db(tmp_path):
    """A pre-Session-33 table without triage columns is upgraded on open()."""
    db = str(tmp_path / "legacy.db")
    con = sqlite3.connect(db)
    con.execute(
        """CREATE TABLE incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL NOT NULL,
            alert_type TEXT NOT NULL, level TEXT NOT NULL, src_ip TEXT,
            dst_ip TEXT, description TEXT, verdict TEXT, score INTEGER,
            intel_summary TEXT, intel_json TEXT, pcap_path TEXT,
            pcap_bytes INTEGER, status TEXT DEFAULT 'open')"""
    )
    con.execute(
        "INSERT INTO incidents (created_at, alert_type, level, status) "
        "VALUES (?,?,?,?)", (time.time(), "OLD", "HIGH", "open")
    )
    con.commit()
    con.close()

    store = IncidentStore(db).open()
    cols = {r["name"] for r in store._conn.execute("PRAGMA table_info(incidents)")}
    assert {"priority", "assignee", "hits", "last_seen"} <= cols
    # legacy row still queryable, and a fresh insert works
    assert store.query(limit=10)
    iid = store.insert(_inc())
    assert store.get(iid)["priority"] == "high"
