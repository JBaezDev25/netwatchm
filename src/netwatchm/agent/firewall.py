"""Firewall mitigation — Phase 5.

Adds auto-expiring ufw deny rules for individual IPs. Three components:

* :class:`BlockEntry` — dataclass for one block record
* :class:`FirewallStore` — JSON sidecar at ``/var/lib/netwatchm/agent_blocks.json``
* :class:`FirewallController` — invokes ufw via subprocess (sudo, no shell)
* :func:`run_firewall_reaper` — async background task that removes expired blocks

Hard safety properties:

- Every rule has a TTL (default 1 h, hard cap 24 h enforced in guardrails)
- IP literals are validated by :mod:`ipaddress` *before* the subprocess call
- subprocess uses ``list`` args (no shell, no metacharacter injection)
- ufw is invoked via sudo with a tight sudoers drop-in (see
  ``scripts/install-firewall-sudoers.sh``) that whitelists only the
  precise ufw subcommands this module needs.
- Reaper runs independently of the agent tick cadence — expired rules
  get cleaned up even if the agent's LLM call is hanging.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .audit import AuditLog

logger = logging.getLogger("netwatchm.agent.firewall")


def _default_data_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "netwatchm"
    return Path("/var/lib/netwatchm")


# Port regex: integer 1..65535. Used as a final fence before subprocess.
_PORT_RE = re.compile(r"^[0-9]{1,5}$")


# ---------- Entry ----------


@dataclass
class BlockEntry:
    """One firewall block. Persisted to JSON, applied via ufw."""

    id: str
    ip: str
    port: int | None       # None = block all ports for this ip
    protocol: str | None   # 'tcp' | 'udp' | None (None = all)
    added_at: float
    expires_at: float
    reason: str
    decision_id: int | None
    rolled_back: bool = False


# ---------- Store ----------


class FirewallStore:
    """Append + soft-delete JSON store for active blocks.

    Mirrors :class:`AgentWhitelistStore` so the audit story is consistent:
    expired/rolled-back entries stay on disk for visibility but are
    excluded from ``active_entries``."""

    def __init__(self, path: str | None = None) -> None:
        if path is None:
            path = str(_default_data_dir() / "agent_blocks.json")
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
        port: int | None,
        protocol: str | None,
        ttl_seconds: int,
        reason: str,
        decision_id: int | None,
    ) -> BlockEntry:
        entry = BlockEntry(
            id=str(uuid.uuid4()),
            ip=ip,
            port=port,
            protocol=(protocol.lower() if protocol else None),
            added_at=time.time(),
            expires_at=time.time() + ttl_seconds,
            reason=reason[:500],
            decision_id=decision_id,
        )
        data = self._load()
        data["entries"].append(asdict(entry))
        self._save(data)
        return entry

    def mark_rolled_back(self, entry_id: str) -> dict | None:
        """Mark the matching active entry rolled back. Returns the entry
        dict that was touched (for the reaper / API to inspect ip+port)."""
        data = self._load()
        for e in data["entries"]:
            if e.get("id") == entry_id and not e.get("rolled_back"):
                e["rolled_back"] = True
                self._save(data)
                return e
        return None

    def expired_active(self, *, now: float | None = None) -> list[dict]:
        """Return entries whose TTL has passed but are not yet rolled_back."""
        cutoff = now if now is not None else time.time()
        return [
            e
            for e in self._load().get("entries", [])
            if not e.get("rolled_back") and float(e.get("expires_at", 0)) <= cutoff
        ]

    def active_entries(self, *, now: float | None = None) -> list[dict]:
        cutoff = now if now is not None else time.time()
        return [
            e
            for e in self._load().get("entries", [])
            if not e.get("rolled_back") and float(e.get("expires_at", 0)) > cutoff
        ]

    def count_active(self, *, now: float | None = None) -> int:
        return len(self.active_entries(now=now))


# ---------- Controller ----------


class FirewallController:
    """Wraps ``ufw`` subcommands. Validates args, no shell, no positional rules.

    All mutating calls use ``ufw deny from <ip> [to any port <p>]`` (append)
    and ``ufw delete deny from <ip> [to any port <p>]`` (remove). Both are
    idempotent — ufw silently no-ops if the rule already / no longer exists.
    Removing by content (not by position number) avoids the "positions
    shift when other rules are added" footgun.
    """

    def __init__(
        self,
        *,
        ufw_binary: str | None = None,
        sudo_binary: str | None = None,
        timeout_seconds: int = 15,
    ) -> None:
        if ufw_binary is None:
            ufw_binary = shutil.which("ufw") or "/usr/sbin/ufw"
        if sudo_binary is None:
            sudo_binary = shutil.which("sudo") or "/usr/bin/sudo"
        self.ufw = ufw_binary
        self.sudo = sudo_binary
        self.timeout_seconds = timeout_seconds

    # --- arg validators (final fence before subprocess) ---

    @staticmethod
    def _validated_ip(ip: str) -> str:
        s = str(ip).strip()
        ipaddress.ip_address(s)  # raises on bad input or CIDR
        return s

    @staticmethod
    def _validated_port(port: int | None) -> str | None:
        if port is None:
            return None
        s = str(int(port))
        if not _PORT_RE.fullmatch(s):
            raise ValueError(f"invalid port: {port!r}")
        n = int(s)
        if not (1 <= n <= 65535):
            raise ValueError(f"port out of range: {n}")
        return s

    def _build_args(self, *, ip: str, port: int | None, action: str) -> list[str]:
        """action == 'add' or 'remove'."""
        ip_s = self._validated_ip(ip)
        port_s = self._validated_port(port)
        cmd = [self.sudo, "-n", self.ufw]
        if action == "add":
            cmd += ["deny", "from", ip_s]
        elif action == "remove":
            cmd += ["delete", "deny", "from", ip_s]
        else:
            raise ValueError(f"invalid action: {action!r}")
        if port_s is not None:
            cmd += ["to", "any", "port", port_s]
        return cmd

    def _run(self, args: list[str]) -> tuple[int, str, str]:
        logger.debug("running %s", args)
        try:
            cp = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            return cp.returncode, cp.stdout, cp.stderr
        except subprocess.TimeoutExpired as exc:
            return 124, "", f"timeout: {exc}"
        except FileNotFoundError as exc:
            return 127, "", f"binary not found: {exc}"

    # --- public API ---

    def add_block(self, *, ip: str, port: int | None = None) -> dict:
        args = self._build_args(ip=ip, port=port, action="add")
        rc, out, err = self._run(args)
        return {
            "ok": rc == 0,
            "returncode": rc,
            "stdout_tail": (out or "")[-500:],
            "stderr_tail": (err or "")[-500:],
            "argv": args,
        }

    def remove_block(self, *, ip: str, port: int | None = None) -> dict:
        args = self._build_args(ip=ip, port=port, action="remove")
        rc, out, err = self._run(args)
        # ufw delete returns 0 on success; non-zero on "Could not delete
        # non-existent rule" — treat that as a soft success since the
        # desired end-state (no rule) is already met.
        soft_ok = rc != 0 and "Could not delete non-existent rule" in (err or out)
        return {
            "ok": rc == 0 or soft_ok,
            "returncode": rc,
            "stdout_tail": (out or "")[-500:],
            "stderr_tail": (err or "")[-500:],
            "argv": args,
            "soft_ok": soft_ok,
        }


# ---------- Reaper ----------


async def run_firewall_reaper(
    *,
    store: FirewallStore,
    controller: FirewallController,
    audit: "AuditLog | None",
    stop_event: asyncio.Event,
    interval_seconds: int = 60,
) -> None:
    """Background loop: every ``interval_seconds`` remove expired ufw rules.

    Independent of the agent tick. Even if the LLM call is hanging or the
    agent loop crashed, the reaper continues to enforce TTLs so no block
    survives past its expiry.

    Records each removal in the audit DB as a synthetic ``__reaper__``
    tool call so the action remains visible alongside agent decisions.
    """
    logger.info(
        "firewall reaper starting (interval=%ds, store=%s)",
        interval_seconds, store.path,
    )
    try:
        while not stop_event.is_set():
            try:
                _process_expired_once(store=store, controller=controller, audit=audit)
            except Exception:  # noqa: BLE001
                logger.exception("reaper tick failed")
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
            except asyncio.TimeoutError:
                continue
    finally:
        logger.info("firewall reaper stopped")


def _process_expired_once(
    *,
    store: FirewallStore,
    controller: FirewallController,
    audit: "AuditLog | None",
) -> int:
    """Remove all expired blocks. Returns count removed. Synchronous;
    called from the async reaper or from tests directly."""
    expired = store.expired_active()
    if not expired:
        return 0
    n = 0
    for e in expired:
        ip = str(e.get("ip") or "")
        port_raw = e.get("port")
        port = int(port_raw) if port_raw is not None else None
        result = controller.remove_block(ip=ip, port=port)
        # Mark rolled_back regardless of ufw outcome — the TTL has passed
        # so we never want to keep the entry "active" in our store.
        store.mark_rolled_back(str(e.get("id") or ""))
        n += 1
        if audit is not None:
            try:
                audit.record_tool_call(
                    decision_id=int(e.get("decision_id") or 0) or -1,
                    tool_name="__reaper__",
                    args={"entry_id": e.get("id"), "ip": ip, "port": port},
                    status="executed" if result.get("ok") else "error",
                    result=result,
                    blocked_reason=(None if result.get("ok") else "ufw remove failed"),
                )
            except Exception:  # noqa: BLE001
                logger.exception("reaper audit log failed")
    if n:
        logger.info("reaper removed %d expired block(s)", n)
    return n
