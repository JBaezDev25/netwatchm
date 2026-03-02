"""Tests for EventStore."""
from __future__ import annotations

import time
from datetime import datetime

import pytest

from netwatchm.alerts.event_store import EventStore, RETENTION_HOURS
from netwatchm.models import Alert, ThreatLevel


def _alert(
    alert_type: str = "PORT_SCAN",
    level: ThreatLevel = ThreatLevel.HIGH,
    src_ip: str = "192.168.1.5",
    dst_ip: str = "10.0.0.1",
    description: str = "test alert",
    ts: float | None = None,
) -> Alert:
    a = Alert(
        alert_type=alert_type,
        level=level,
        src_ip=src_ip,
        dst_ip=dst_ip,
        description=description,
    )
    if ts is not None:
        # Override the auto-generated timestamp
        object.__setattr__(a, "timestamp", datetime.fromtimestamp(ts))
    return a


@pytest.fixture
def store(tmp_path):
    db = str(tmp_path / "events.db")
    with EventStore(db) as s:
        yield s


class TestEventStore:
    def test_empty_query_returns_empty(self, store):
        assert store.query() == []

    def test_insert_and_query(self, store):
        store.insert(_alert())
        results = store.query()
        assert len(results) == 1
        assert results[0]["alert_type"] == "PORT_SCAN"
        assert results[0]["level"] == "HIGH"
        assert results[0]["src_ip"] == "192.168.1.5"

    def test_multiple_events_newest_first(self, store):
        store.insert(_alert(alert_type="A", ts=time.time() - 10))
        store.insert(_alert(alert_type="B", ts=time.time()))
        results = store.query()
        assert results[0]["alert_type"] == "B"
        assert results[1]["alert_type"] == "A"

    def test_filter_by_type(self, store):
        store.insert(_alert(alert_type="PORT_SCAN"))
        store.insert(_alert(alert_type="TOR_EXIT"))
        results = store.query(alert_type="PORT_SCAN")
        assert len(results) == 1
        assert results[0]["alert_type"] == "PORT_SCAN"

    def test_filter_by_level(self, store):
        store.insert(_alert(level=ThreatLevel.HIGH))
        store.insert(_alert(level=ThreatLevel.LOW))
        results = store.query(level="HIGH")
        assert len(results) == 1
        assert results[0]["level"] == "HIGH"

    def test_filter_by_ip_src(self, store):
        store.insert(_alert(src_ip="1.2.3.4", dst_ip="5.6.7.8"))
        store.insert(_alert(src_ip="9.9.9.9", dst_ip="8.8.8.8"))
        results = store.query(ip="1.2.3.4")
        assert len(results) == 1
        assert results[0]["src_ip"] == "1.2.3.4"

    def test_filter_by_ip_dst(self, store):
        store.insert(_alert(src_ip="1.2.3.4", dst_ip="5.6.7.8"))
        store.insert(_alert(src_ip="9.9.9.9", dst_ip="8.8.8.8"))
        results = store.query(ip="5.6.7.8")
        assert len(results) == 1
        assert results[0]["dst_ip"] == "5.6.7.8"

    def test_limit_respected(self, store):
        for i in range(10):
            store.insert(_alert(description=f"event {i}"))
        results = store.query(limit=3)
        assert len(results) == 3

    def test_retention_prunes_old_events(self, store):
        old_ts = time.time() - (RETENTION_HOURS + 1) * 3600
        store.insert(_alert(alert_type="OLD", ts=old_ts))
        # Inserting a new event triggers the purge
        store.insert(_alert(alert_type="NEW"))
        results = store.query()
        types = [r["alert_type"] for r in results]
        assert "NEW" in types
        assert "OLD" not in types

    def test_distinct_types_empty(self, store):
        assert store.distinct_types() == []

    def test_distinct_types(self, store):
        store.insert(_alert(alert_type="PORT_SCAN"))
        store.insert(_alert(alert_type="TOR_EXIT"))
        store.insert(_alert(alert_type="PORT_SCAN"))
        types = store.distinct_types()
        assert sorted(types) == ["PORT_SCAN", "TOR_EXIT"]

    def test_count(self, store):
        assert store.count() == 0
        store.insert(_alert())
        store.insert(_alert())
        assert store.count() == 2

    def test_all_fields_stored(self, store):
        store.insert(_alert(
            alert_type="BRUTE_FORCE",
            level=ThreatLevel.MEDIUM,
            src_ip="10.0.0.5",
            dst_ip="10.0.0.1",
            description="many attempts",
        ))
        r = store.query()[0]
        assert r["alert_type"] == "BRUTE_FORCE"
        assert r["level"] == "MEDIUM"
        assert r["src_ip"] == "10.0.0.5"
        assert r["dst_ip"] == "10.0.0.1"
        assert r["description"] == "many attempts"
        assert r["timestamp"] > 0
