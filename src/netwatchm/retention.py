"""15-day uniform retention sweep (Session 29).

Cleans up application data that has no built-in pruner of its own:

* ``agent_actions.db`` — agent audit log (decisions + tool calls); rows
  older than the retention window are deleted in cascade (decisions first
  filter the set of decision_ids whose tool calls should also go).
* ``agent_whitelist.json`` — rolled-back and expired entries are
  physically removed from the JSON file (the live store soft-deletes
  forever otherwise).
* ``agent_blocks.json`` — same, for firewall blocks.

This module does NOT touch:

* ``events.db``, ``flows.db``, ``flow_history.db`` — their own pruners
  enforce retention on every insert; updating their `retention_hours`
  config knob is enough to take effect.
* ``/var/log/netwatchm/*.log`` — handled by the system ``logrotate``
  drop-in installed via ``scripts/install-log-retention.sh``.

Runs once at process startup (catches up any accumulated backlog after
an upgrade) and then on a 24 h cadence inside :func:`run_retention_loop`.
Safe to interrupt — every operation is idempotent.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .agent.firewall import FirewallStore
    from .agent.state import AgentWhitelistStore

logger = logging.getLogger("netwatchm.retention")


DEFAULT_RETENTION_DAYS = 15
DEFAULT_INTERVAL_SECONDS = 86400  # 24 h


# ---------- Audit DB ----------


def prune_audit_db(
    audit_db_path: str, *, retention_days: int = DEFAULT_RETENTION_DAYS
) -> tuple[int, int]:
    """Delete ``agent_decisions`` (and cascade their ``agent_tool_calls``)
    older than ``retention_days``.

    Returns ``(decisions_deleted, tool_calls_deleted)``. Safe to call when
    the DB doesn't exist yet — returns ``(0, 0)`` in that case.
    """
    if not Path(audit_db_path).exists():
        return (0, 0)
    cutoff = time.time() - retention_days * 86400
    conn = sqlite3.connect(audit_db_path)
    try:
        # Cascade by hand — the FK declared in audit.py is informational
        # (SQLite doesn't enforce FKs unless PRAGMA foreign_keys=ON).
        cur = conn.execute(
            "DELETE FROM agent_tool_calls WHERE decision_id IN "
            "(SELECT id FROM agent_decisions WHERE ts < ?)",
            (cutoff,),
        )
        tool_calls_deleted = cur.rowcount or 0
        cur = conn.execute("DELETE FROM agent_decisions WHERE ts < ?", (cutoff,))
        decisions_deleted = cur.rowcount or 0
        conn.commit()
        # Reclaim file size after a large delete. VACUUM is heavy but
        # this runs once a day so the cost is acceptable.
        if decisions_deleted:
            conn.execute("VACUUM")
        return decisions_deleted, tool_calls_deleted
    except sqlite3.OperationalError as exc:
        # Schema mismatch (e.g. tests with a half-built DB) — log and return
        # zero rather than crashing the retention loop.
        logger.warning("prune_audit_db skipped: %s", exc)
        return (0, 0)
    finally:
        conn.close()


# ---------- JSON-sidecar compactors ----------


def compact_whitelist_store(
    store: "AgentWhitelistStore", *, retention_days: int = DEFAULT_RETENTION_DAYS
) -> int:
    """Physically remove entries that are rolled-back AND older than the
    retention window, or expired AND older than the retention window.

    Returns the count physically removed. Active entries (still within TTL
    and not rolled back) are always preserved regardless of age.
    """
    return _compact_json_store(
        path=store.path,
        retention_seconds=retention_days * 86400,
        timestamp_field="added_at",
    )


def compact_blocks_store(
    store: "FirewallStore", *, retention_days: int = DEFAULT_RETENTION_DAYS
) -> int:
    """Physically remove firewall block entries that are rolled-back AND
    older than the retention window. Returns count removed."""
    return _compact_json_store(
        path=store.path,
        retention_seconds=retention_days * 86400,
        timestamp_field="added_at",
    )


def _compact_json_store(
    *, path: str, retention_seconds: float, timestamp_field: str
) -> int:
    """Shared implementation. Reads ``path``, drops entries that are
    (rolled_back OR expired) AND have ``timestamp_field < now - retention``,
    writes the file back atomically. Returns count removed."""
    p = Path(path)
    if not p.exists():
        return 0
    try:
        data = json.loads(p.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("compact_json_store cannot read %s: %s", path, exc)
        return 0
    if not isinstance(data, dict) or "entries" not in data:
        return 0

    cutoff = time.time() - retention_seconds
    kept: list[dict] = []
    removed = 0
    for e in data["entries"]:
        ts = float(e.get(timestamp_field) or 0)
        expires_at = float(e.get("expires_at") or 0)
        is_rolled_back = bool(e.get("rolled_back"))
        is_expired = expires_at > 0 and expires_at <= time.time()
        is_too_old = ts < cutoff
        # Keep iff: not rolled-back AND not expired (i.e. still in active
        # use), OR younger than retention (still useful for audit history).
        if (not is_rolled_back and not is_expired) or not is_too_old:
            kept.append(e)
        else:
            removed += 1

    if removed == 0:
        return 0

    data["entries"] = kept
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(p)
    return removed


# ---------- Async loop ----------


async def run_retention_loop(
    *,
    audit_db_path: str,
    whitelist_store: "AgentWhitelistStore | None" = None,
    blocks_store: "FirewallStore | None" = None,
    stop_event: asyncio.Event,
    retention_days: int = DEFAULT_RETENTION_DAYS,
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
) -> None:
    """Background task: sweep all retention targets every ``interval_seconds``.

    Sweeps once at startup so a process that has been down for >1 day still
    cleans up its backlog. Each sweep is wrapped so an error in one target
    does not skip the others or kill the loop."""
    logger.info(
        "retention loop starting (retention=%dd, interval=%ds)",
        retention_days, interval_seconds,
    )
    # Initial sweep so a restart catches backlog immediately.
    _sweep_once(
        audit_db_path=audit_db_path,
        whitelist_store=whitelist_store,
        blocks_store=blocks_store,
        retention_days=retention_days,
    )
    try:
        while not stop_event.is_set():
            try:
                await asyncio.wait_for(
                    stop_event.wait(), timeout=interval_seconds
                )
                # stop_event fired — exit
                break
            except asyncio.TimeoutError:
                _sweep_once(
                    audit_db_path=audit_db_path,
                    whitelist_store=whitelist_store,
                    blocks_store=blocks_store,
                    retention_days=retention_days,
                )
    finally:
        logger.info("retention loop stopped")


def _sweep_once(
    *,
    audit_db_path: str,
    whitelist_store: "AgentWhitelistStore | None",
    blocks_store: "FirewallStore | None",
    retention_days: int,
) -> None:
    """One pass over all retention targets. Each step is isolated so a
    failure in one does not skip the next."""
    try:
        decisions, tool_calls = prune_audit_db(
            audit_db_path, retention_days=retention_days
        )
        if decisions or tool_calls:
            logger.info(
                "audit DB pruned: %d decisions, %d tool calls (>%dd)",
                decisions, tool_calls, retention_days,
            )
    except Exception:  # noqa: BLE001
        logger.exception("audit DB prune failed")

    if whitelist_store is not None:
        try:
            n = compact_whitelist_store(
                whitelist_store, retention_days=retention_days
            )
            if n:
                logger.info("whitelist store compacted: %d entries removed", n)
        except Exception:  # noqa: BLE001
            logger.exception("whitelist compaction failed")

    if blocks_store is not None:
        try:
            n = compact_blocks_store(
                blocks_store, retention_days=retention_days
            )
            if n:
                logger.info("blocks store compacted: %d entries removed", n)
        except Exception:  # noqa: BLE001
            logger.exception("blocks compaction failed")
