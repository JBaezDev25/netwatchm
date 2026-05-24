"""Session 29 — retention sweep tests."""
from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from pathlib import Path

import pytest

from netwatchm.agent.audit import AuditLog
from netwatchm.agent.firewall import FirewallStore
from netwatchm.agent.state import AgentWhitelistStore
from netwatchm.retention import (
    DEFAULT_INTERVAL_SECONDS,
    DEFAULT_RETENTION_DAYS,
    compact_blocks_store,
    compact_whitelist_store,
    prune_audit_db,
    run_retention_loop,
)


# ---------- Audit DB ----------


def _seed_decision(audit: AuditLog, *, ts: float, model: str = "m") -> int:
    """Insert a decision row with a custom timestamp; return its id."""
    cur = audit._conn.execute(
        "INSERT INTO agent_decisions "
        "(ts, model, mode, events_seen, max_severity, rationale, raw_response, error) "
        "VALUES (?, ?, 'live', 0, NULL, NULL, NULL, NULL)",
        (ts, model),
    )
    audit._conn.commit()
    return int(cur.lastrowid)


def test_prune_audit_db_removes_old_decisions(tmp_path: Path) -> None:
    db = tmp_path / "audit.db"
    audit = AuditLog(str(db)).open()
    try:
        old = _seed_decision(audit, ts=time.time() - 30 * 86400)  # 30 days old
        new = _seed_decision(audit, ts=time.time() - 5 * 86400)   # 5 days old
        for d_id in (old, new):
            audit.record_tool_call(
                decision_id=d_id, tool_name="x", args={}, status="executed"
            )
    finally:
        audit.close()

    decisions, tool_calls = prune_audit_db(str(db), retention_days=15)
    assert decisions == 1, "should have removed 1 decision >15d old"
    assert tool_calls == 1, "should cascade-remove its tool call"

    conn = sqlite3.connect(str(db))
    try:
        n_dec = conn.execute("SELECT COUNT(*) FROM agent_decisions").fetchone()[0]
        n_tc = conn.execute("SELECT COUNT(*) FROM agent_tool_calls").fetchone()[0]
    finally:
        conn.close()
    assert n_dec == 1
    assert n_tc == 1


def test_prune_audit_db_missing_file_returns_zero(tmp_path: Path) -> None:
    decisions, tool_calls = prune_audit_db(str(tmp_path / "nope.db"))
    assert (decisions, tool_calls) == (0, 0)


def test_prune_audit_db_noop_when_nothing_old(tmp_path: Path) -> None:
    db = tmp_path / "audit.db"
    audit = AuditLog(str(db)).open()
    try:
        _seed_decision(audit, ts=time.time() - 86400)   # 1 day old
        _seed_decision(audit, ts=time.time() - 5 * 86400)  # 5 days old
    finally:
        audit.close()
    decisions, tool_calls = prune_audit_db(str(db), retention_days=15)
    assert decisions == 0
    assert tool_calls == 0


# ---------- Whitelist compactor ----------


def test_compact_whitelist_removes_old_rolled_back(tmp_path: Path) -> None:
    p = tmp_path / "wl.json"
    store = AgentWhitelistStore(str(p))
    # Active recent — must survive
    store.add(
        ip="8.8.8.8", scope="global", alert_type=None,
        ttl_hours=72, reason="active", decision_id=1,
    )
    # Rolled-back, recent — must survive
    e_recent = store.add(
        ip="1.1.1.1", scope="global", alert_type=None,
        ttl_hours=72, reason="recent-rollback", decision_id=2,
    )
    store.rollback_by_id(e_recent.id)
    # Rolled-back, old — must be removed
    e_old = store.add(
        ip="9.9.9.9", scope="global", alert_type=None,
        ttl_hours=72, reason="old-rollback", decision_id=3,
    )
    store.rollback_by_id(e_old.id)
    # Hand-edit the old entry's added_at to be 30 days ago
    data = json.loads(p.read_text())
    for e in data["entries"]:
        if e["id"] == e_old.id:
            e["added_at"] = time.time() - 30 * 86400
    p.write_text(json.dumps(data))

    n = compact_whitelist_store(store, retention_days=15)
    assert n == 1

    remaining = json.loads(p.read_text())["entries"]
    ids = {e["id"] for e in remaining}
    assert e_old.id not in ids
    assert e_recent.id in ids


def test_compact_whitelist_keeps_old_but_active(tmp_path: Path) -> None:
    """An active entry older than retention must NOT be touched — it's
    still in use. Only rolled-back/expired entries get purged."""
    p = tmp_path / "wl.json"
    store = AgentWhitelistStore(str(p))
    e = store.add(
        ip="8.8.8.8", scope="global", alert_type=None,
        ttl_hours=72, reason="still active", decision_id=1,
    )
    data = json.loads(p.read_text())
    data["entries"][0]["added_at"] = time.time() - 30 * 86400  # 30 days
    # but expires_at still in the future
    p.write_text(json.dumps(data))

    n = compact_whitelist_store(store, retention_days=15)
    assert n == 0
    assert len(json.loads(p.read_text())["entries"]) == 1


def test_compact_whitelist_missing_file(tmp_path: Path) -> None:
    store = AgentWhitelistStore(str(tmp_path / "nope.json"))
    assert compact_whitelist_store(store) == 0


# ---------- Blocks compactor ----------


def test_compact_blocks_removes_old_rolled_back(tmp_path: Path) -> None:
    p = tmp_path / "blocks.json"
    store = FirewallStore(str(p))
    # Active recent
    store.add(
        ip="8.8.8.8", port=None, protocol=None,
        ttl_seconds=3600, reason="active", decision_id=1,
    )
    # Rolled-back, old
    e_old = store.add(
        ip="9.9.9.9", port=80, protocol=None,
        ttl_seconds=3600, reason="old", decision_id=2,
    )
    store.mark_rolled_back(e_old.id)
    data = json.loads(p.read_text())
    for e in data["entries"]:
        if e["id"] == e_old.id:
            e["added_at"] = time.time() - 30 * 86400
    p.write_text(json.dumps(data))

    n = compact_blocks_store(store, retention_days=15)
    assert n == 1
    ids = {e["id"] for e in json.loads(p.read_text())["entries"]}
    assert e_old.id not in ids


def test_compact_blocks_removes_old_expired(tmp_path: Path) -> None:
    """Even without explicit rollback, an entry whose TTL passed
    long ago should be purged once it's beyond the retention window."""
    p = tmp_path / "blocks.json"
    store = FirewallStore(str(p))
    e = store.add(
        ip="8.8.8.8", port=None, protocol=None,
        ttl_seconds=60, reason="x", decision_id=1,
    )
    data = json.loads(p.read_text())
    data["entries"][0]["added_at"] = time.time() - 30 * 86400
    data["entries"][0]["expires_at"] = time.time() - 30 * 86400 + 60
    p.write_text(json.dumps(data))

    n = compact_blocks_store(store, retention_days=15)
    assert n == 1


# ---------- run_retention_loop ----------


@pytest.mark.asyncio
async def test_run_retention_loop_does_initial_sweep_then_stops(tmp_path: Path) -> None:
    """The loop must do an initial sweep at startup (so a restart catches
    backlog) and then exit cleanly when stop_event fires before the next
    interval."""
    db = tmp_path / "audit.db"
    audit = AuditLog(str(db)).open()
    try:
        _seed_decision(audit, ts=time.time() - 30 * 86400)
    finally:
        audit.close()

    stop_event = asyncio.Event()

    async def stop_soon() -> None:
        await asyncio.sleep(0.05)
        stop_event.set()

    asyncio.create_task(stop_soon())
    await asyncio.wait_for(
        run_retention_loop(
            audit_db_path=str(db),
            whitelist_store=None,
            blocks_store=None,
            stop_event=stop_event,
            retention_days=15,
            interval_seconds=999,   # large — only initial sweep + stop
        ),
        timeout=5.0,
    )
    # Initial sweep should have nuked the 30-day-old decision
    conn = sqlite3.connect(str(db))
    try:
        n = conn.execute("SELECT COUNT(*) FROM agent_decisions").fetchone()[0]
    finally:
        conn.close()
    assert n == 0


def test_defaults_are_15_days() -> None:
    assert DEFAULT_RETENTION_DAYS == 15
    assert DEFAULT_INTERVAL_SECONDS == 86400
