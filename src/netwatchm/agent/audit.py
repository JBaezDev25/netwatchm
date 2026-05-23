"""Append-only SQLite audit log for agent decisions and tool calls."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any


def _default_db() -> str:
    if sys.platform == "win32":
        return str(
            Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
            / "netwatchm"
            / "agent_actions.db"
        )
    return "/var/lib/netwatchm/agent_actions.db"


DEFAULT_AUDIT_DB = _default_db()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_decisions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,
    model           TEXT    NOT NULL,
    mode            TEXT    NOT NULL,   -- 'dry_run' or 'live'
    events_seen     INTEGER NOT NULL,
    max_severity    TEXT,
    rationale       TEXT,
    raw_response    TEXT,
    error           TEXT
);
CREATE INDEX IF NOT EXISTS idx_decisions_ts ON agent_decisions (ts);

CREATE TABLE IF NOT EXISTS agent_tool_calls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id     INTEGER NOT NULL,
    ts              REAL    NOT NULL,
    tool_name       TEXT    NOT NULL,
    args_json       TEXT    NOT NULL,
    status          TEXT    NOT NULL,   -- proposed|executed|blocked|rolled_back|error
    result_json     TEXT,
    blocked_reason  TEXT,
    FOREIGN KEY (decision_id) REFERENCES agent_decisions(id)
);
CREATE INDEX IF NOT EXISTS idx_calls_decision ON agent_tool_calls (decision_id);
CREATE INDEX IF NOT EXISTS idx_calls_ts       ON agent_tool_calls (ts);
CREATE INDEX IF NOT EXISTS idx_calls_status   ON agent_tool_calls (status);
"""


class AuditLog:
    """Append-only audit log. Writes only — never UPDATE/DELETE on decisions.

    Tool-call status is the one mutable field, transitioning through
    proposed → executed | blocked | error, and optionally → rolled_back later.
    """

    def __init__(self, db_path: str = DEFAULT_AUDIT_DB) -> None:
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None

    def open(self) -> "AuditLog":
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        return self

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "AuditLog":
        return self.open()

    def __exit__(self, *_: object) -> None:
        self.close()

    def record_decision(
        self,
        *,
        model: str,
        mode: str,
        events_seen: int,
        max_severity: str | None,
        rationale: str | None,
        raw_response: str | None,
        error: str | None = None,
    ) -> int:
        assert self._conn, "AuditLog not open"
        cur = self._conn.execute(
            "INSERT INTO agent_decisions "
            "(ts, model, mode, events_seen, max_severity, rationale, raw_response, error) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                time.time(),
                model,
                mode,
                events_seen,
                max_severity,
                rationale,
                raw_response,
                error,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid or 0)

    def record_tool_call(
        self,
        *,
        decision_id: int,
        tool_name: str,
        args: dict,
        status: str,
        result: Any = None,
        blocked_reason: str | None = None,
    ) -> int:
        assert self._conn, "AuditLog not open"
        cur = self._conn.execute(
            "INSERT INTO agent_tool_calls "
            "(decision_id, ts, tool_name, args_json, status, result_json, blocked_reason) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                decision_id,
                time.time(),
                tool_name,
                json.dumps(args, default=str),
                status,
                json.dumps(result, default=str) if result is not None else None,
                blocked_reason,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid or 0)

    def mark_call_status(
        self,
        call_id: int,
        status: str,
        *,
        result: Any = None,
        blocked_reason: str | None = None,
    ) -> None:
        """Transition a tool call's status (proposed → executed/blocked/etc).

        The only mutable field on agent_tool_calls — the rest stays immutable.
        """
        assert self._conn, "AuditLog not open"
        sets = ["status = ?"]
        params: list[Any] = [status]
        if result is not None:
            sets.append("result_json = ?")
            params.append(json.dumps(result, default=str))
        if blocked_reason is not None:
            sets.append("blocked_reason = ?")
            params.append(blocked_reason)
        params.append(call_id)
        self._conn.execute(
            f"UPDATE agent_tool_calls SET {', '.join(sets)} WHERE id = ?",
            params,
        )
        self._conn.commit()

    def recent_decisions(self, limit: int = 50) -> list[dict]:
        assert self._conn, "AuditLog not open"
        cur = self._conn.execute(
            "SELECT id, ts, model, mode, events_seen, max_severity, rationale, error "
            "FROM agent_decisions ORDER BY ts DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]

    def calls_for_decision(self, decision_id: int) -> list[dict]:
        assert self._conn, "AuditLog not open"
        cur = self._conn.execute(
            "SELECT id, ts, tool_name, args_json, status, result_json, blocked_reason "
            "FROM agent_tool_calls WHERE decision_id = ? ORDER BY ts ASC",
            (decision_id,),
        )
        return [dict(r) for r in cur.fetchall()]
