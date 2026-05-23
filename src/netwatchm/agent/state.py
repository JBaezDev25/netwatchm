"""Agent-managed state files.

The agent never edits /etc/netwatchm/netwatchm.yaml directly — it writes to
side-car JSON files under /var/lib/netwatchm/ that the main monitor
hot-reloads:

  * ``agent_whitelist.json`` — TTL-bounded whitelist entries the agent has
    added. The main monitor's ``alert_dispatch_loop`` checks this file
    (cached for 5 s) after the static whitelist + per-detector whitelist,
    so additions take effect without restarting the service.
  * ``suppressed.json`` — already used by the existing events portal's
    Suppress button (``alert_dispatch_loop`` already caches and applies
    it). The agent can append to / remove from the ``types`` list here.

Both files are tolerant of missing-or-malformed inputs (return empty state)
so a write error never silently leaves the system in a half-mutated state.
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


def _default_data_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "netwatchm"
    return Path("/var/lib/netwatchm")


@dataclass
class WhitelistEntry:
    id: str
    ip: str
    scope: str               # 'global' or 'detector'
    alert_type: str | None   # required when scope == 'detector'
    added_at: float
    expires_at: float
    reason: str
    decision_id: int | None
    rolled_back: bool = False


class AgentWhitelistStore:
    """Append + soft-delete store. TTL-expired entries are skipped at read
    time but stay on disk for audit visibility."""

    def __init__(self, path: str | None = None) -> None:
        if path is None:
            path = str(_default_data_dir() / "agent_whitelist.json")
        self.path = path

    def _load(self) -> dict:
        p = Path(self.path)
        if not p.exists():
            return {"version": 1, "entries": []}
        try:
            data = json.loads(p.read_text())
            if not isinstance(data, dict) or "entries" not in data:
                return {"version": 1, "entries": []}
            return data
        except Exception:  # noqa: BLE001
            return {"version": 1, "entries": []}

    def _save(self, data: dict) -> None:
        p = Path(self.path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(p)  # atomic on POSIX

    def add(
        self,
        *,
        ip: str,
        scope: str,
        alert_type: str | None,
        ttl_hours: int,
        reason: str,
        decision_id: int | None,
    ) -> WhitelistEntry:
        entry = WhitelistEntry(
            id=str(uuid.uuid4()),
            ip=ip,
            scope=scope,
            alert_type=(alert_type or None),
            added_at=time.time(),
            expires_at=time.time() + ttl_hours * 3600,
            reason=reason[:500],
            decision_id=decision_id,
        )
        data = self._load()
        data["entries"].append(asdict(entry))
        self._save(data)
        return entry

    def remove(
        self, *, ip: str, scope: str, alert_type: str | None = None
    ) -> int:
        """Mark all matching active entries rolled_back. Returns count touched."""
        data = self._load()
        n = 0
        for e in data["entries"]:
            if e.get("rolled_back"):
                continue
            if e.get("ip") != ip:
                continue
            if e.get("scope") != scope:
                continue
            if scope == "detector" and e.get("alert_type") != alert_type:
                continue
            e["rolled_back"] = True
            n += 1
        if n:
            self._save(data)
        return n

    def rollback_by_id(self, entry_id: str) -> bool:
        data = self._load()
        for e in data["entries"]:
            if e.get("id") == entry_id and not e.get("rolled_back"):
                e["rolled_back"] = True
                self._save(data)
                return True
        return False

    def active_entries(self, *, now: float | None = None) -> list[dict]:
        """All entries that are neither rolled back nor expired."""
        cutoff = now if now is not None else time.time()
        return [
            e
            for e in self._load().get("entries", [])
            if not e.get("rolled_back") and (e.get("expires_at", 0) > cutoff)
        ]

    def is_suppressed(self, alert_type: str, src_ip: str) -> bool:
        """Should this (alert_type, src_ip) be filtered by the agent's
        side-car whitelist? Returns True if a matching active entry exists."""
        if not src_ip:
            return False
        atype = (alert_type or "").upper()
        for e in self.active_entries():
            if e.get("ip") != src_ip:
                continue
            if e.get("scope") == "global":
                return True
            if (
                e.get("scope") == "detector"
                and (e.get("alert_type") or "").upper() == atype
            ):
                return True
        return False


class SuppressedTypesStore:
    """Thin wrapper around the existing suppressed.json schema:
    ``{"types": ["PORT_SCAN", ...], "ttl": {alert_type: expires_at}}``

    The legacy events portal writes only ``types``. We additionally write
    ``ttl`` so agent-added suppressions auto-expire. The dispatch loop in
    ``__main__.py`` checks ``types`` and is unaware of ``ttl`` — the agent
    is responsible for honouring its own TTLs and cleaning expired
    entries when it next runs (see ``cleanup_expired``)."""

    def __init__(self, path: str | None = None) -> None:
        if path is None:
            path = str(_default_data_dir() / "suppressed.json")
        self.path = path

    def _load(self) -> dict:
        p = Path(self.path)
        if not p.exists():
            return {"types": [], "ttl": {}}
        try:
            data = json.loads(p.read_text())
            if not isinstance(data, dict):
                return {"types": [], "ttl": {}}
            data.setdefault("types", [])
            data.setdefault("ttl", {})
            return data
        except Exception:  # noqa: BLE001
            return {"types": [], "ttl": {}}

    def _save(self, data: dict) -> None:
        p = Path(self.path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(p)

    def suppress(
        self, alert_type: str, duration_hours: int
    ) -> None:
        atype = alert_type.upper()
        data = self._load()
        if atype not in data["types"]:
            data["types"].append(atype)
        data["ttl"][atype] = time.time() + duration_hours * 3600
        self._save(data)

    def unsuppress(self, alert_type: str) -> bool:
        atype = alert_type.upper()
        data = self._load()
        changed = False
        if atype in data["types"]:
            data["types"].remove(atype)
            changed = True
        if atype in data["ttl"]:
            data["ttl"].pop(atype, None)
            changed = True
        if changed:
            self._save(data)
        return changed

    def cleanup_expired(self, *, now: float | None = None) -> list[str]:
        cutoff = now if now is not None else time.time()
        data = self._load()
        expired = [
            t for t, exp in list(data.get("ttl", {}).items()) if float(exp) <= cutoff
        ]
        if not expired:
            return []
        for t in expired:
            if t in data["types"]:
                data["types"].remove(t)
            data["ttl"].pop(t, None)
        self._save(data)
        return expired

    def active(self) -> list[str]:
        # cleanup_expired before reporting so caller sees current truth
        self.cleanup_expired()
        return list(self._load().get("types", []))
