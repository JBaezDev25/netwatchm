"""Hard programmatic limits on agent actions.

These run *before* the executor. The LLM cannot override them by phrasing,
prompt injection, or argument manipulation — every action method here takes
the same args the LLM provided and returns either ``(True, "")`` (allowed)
or ``(False, "reason")`` (blocked, with a human-readable explanation that
the executor will log to the audit DB).

Three layers of enforcement:

1. **Argument shape** — IPs must parse via ``ipaddress``, single literals
   only (no CIDR blocks accepted from the LLM in Phase 2). Cannot target
   unspecified/multicast/reserved.
2. **State preconditions** — cannot whitelist an IP that fired CRITICAL in
   the last 24 h, cannot suppress CRITICAL alert types, cannot exceed
   per-action TTL caps.
3. **Rate limiting** — counts recent successful tool calls in the audit DB
   and refuses new actions when the per-hour / per-day cap would be
   exceeded.

These caps are intentionally tight — better to reject a useful action
than to let a runaway loop drain Twilio credit or whitelist half the
internet because of a malformed model response.
"""
from __future__ import annotations

import ipaddress
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any


# ---------- Caps ----------


@dataclass
class GuardrailLimits:
    """Tunable per-action caps. Defaults are conservative."""
    max_whitelist_changes_per_hour: int = 5
    max_suppress_changes_per_hour: int = 3
    max_scans_per_hour: int = 10
    max_notifications_per_day: int = 20
    max_suppress_hours: int = 24
    max_whitelist_ttl_hours: int = 72
    max_headline_chars: int = 200
    # Refuse to whitelist an IP that fired a CRITICAL alert in this window
    critical_event_lookback_hours: int = 24
    # Alert types we refuse to suppress no matter what the LLM says
    banned_suppress_types: frozenset[str] = field(
        default_factory=lambda: frozenset({"EXFILTRATION", "MALWARE_DOMAIN"})
    )
    # Severities the agent may emit via send_ntfy_alert
    allowed_notify_severities: frozenset[str] = field(
        default_factory=lambda: frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
    )
    # Tool names allowed in the scan dispatcher
    allowed_scan_types: frozenset[str] = field(
        default_factory=lambda: frozenset({"nmap_ports", "deep_inspect"})
    )


# ---------- Validators ----------


def _validate_target_ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Strict IP literal — no CIDR, no unspecified, no multicast, no reserved.

    The LLM is allowed to *target* a private LAN device or a public host it
    has seen in events. It is *not* allowed to target a network range, a
    multicast group, or anything that resembles ``0.0.0.0``."""
    s = str(value).strip()
    addr = ipaddress.ip_address(s)  # raises ValueError on bad input or CIDR
    if addr.is_unspecified:
        raise ValueError("0.0.0.0 / :: is not a valid target")
    if addr.is_multicast:
        raise ValueError("multicast addresses are not valid targets")
    if addr.is_reserved:
        raise ValueError("reserved addresses are not valid targets")
    return addr


def _validate_alert_type(value: Any) -> str:
    s = str(value).strip().upper()
    if not s or not s.replace("_", "").isalnum():
        raise ValueError(f"invalid alert_type: {value!r}")
    if len(s) > 40:
        raise ValueError("alert_type too long")
    return s


# ---------- Rate counter ----------


def _count_recent_successful(
    audit_db_path: str, tool_name: str, since_ts: float
) -> int:
    """Count audit rows with status='executed' for ``tool_name`` since ``since_ts``."""
    try:
        conn = sqlite3.connect(audit_db_path)
        try:
            cur = conn.execute(
                "SELECT COUNT(*) FROM agent_tool_calls "
                "WHERE tool_name = ? AND status = 'executed' AND ts >= ?",
                (tool_name, since_ts),
            )
            return int(cur.fetchone()[0])
        finally:
            conn.close()
    except sqlite3.OperationalError:
        # DB not yet created → no prior calls
        return 0


# ---------- Guardrails facade ----------


class Guardrails:
    """One place to ask 'may the agent do X?' before the executor does X."""

    def __init__(
        self,
        *,
        audit_db_path: str,
        events_db_path: str,
        limits: GuardrailLimits | None = None,
    ) -> None:
        self.audit_db_path = audit_db_path
        self.events_db_path = events_db_path
        self.limits = limits or GuardrailLimits()

    # ----- whitelist add -----

    def check_add_whitelist(self, args: dict) -> tuple[bool, str]:
        try:
            addr = _validate_target_ip(args.get("ip"))
        except (ValueError, KeyError) as exc:
            return False, f"invalid ip: {exc}"

        scope = str(args.get("scope") or "global").lower()
        if scope not in {"global", "detector"}:
            return False, f"invalid scope: {scope!r} (must be 'global' or 'detector')"

        if scope == "detector":
            try:
                _validate_alert_type(args.get("alert_type"))
            except (ValueError, KeyError) as exc:
                return False, f"invalid alert_type for detector scope: {exc}"

        ttl = int(args.get("ttl_hours", self.limits.max_whitelist_ttl_hours))
        if ttl < 1 or ttl > self.limits.max_whitelist_ttl_hours:
            return (
                False,
                f"ttl_hours must be in [1, {self.limits.max_whitelist_ttl_hours}]",
            )

        # State: refuse to whitelist an IP that fired CRITICAL recently
        if self._has_recent_critical(str(addr)):
            return (
                False,
                f"refusing to whitelist {addr} — fired CRITICAL alert in last "
                f"{self.limits.critical_event_lookback_hours}h",
            )

        # Rate cap
        recent = _count_recent_successful(
            self.audit_db_path, "add_whitelist_entry", time.time() - 3600
        ) + _count_recent_successful(
            self.audit_db_path, "remove_whitelist_entry", time.time() - 3600
        )
        if recent >= self.limits.max_whitelist_changes_per_hour:
            return (
                False,
                f"whitelist rate cap hit: "
                f"{recent}/{self.limits.max_whitelist_changes_per_hour} per hour",
            )

        return True, ""

    # ----- whitelist remove -----

    def check_remove_whitelist(self, args: dict) -> tuple[bool, str]:
        try:
            _validate_target_ip(args.get("ip"))
        except (ValueError, KeyError) as exc:
            return False, f"invalid ip: {exc}"

        scope = str(args.get("scope") or "global").lower()
        if scope not in {"global", "detector"}:
            return False, f"invalid scope: {scope!r}"

        recent = _count_recent_successful(
            self.audit_db_path, "add_whitelist_entry", time.time() - 3600
        ) + _count_recent_successful(
            self.audit_db_path, "remove_whitelist_entry", time.time() - 3600
        )
        if recent >= self.limits.max_whitelist_changes_per_hour:
            return False, (
                f"whitelist rate cap hit: "
                f"{recent}/{self.limits.max_whitelist_changes_per_hour} per hour"
            )
        return True, ""

    # ----- suppress / unsuppress -----

    def check_suppress(self, args: dict) -> tuple[bool, str]:
        try:
            atype = _validate_alert_type(args.get("alert_type"))
        except (ValueError, KeyError) as exc:
            return False, str(exc)

        if atype in self.limits.banned_suppress_types:
            return False, f"refusing to suppress {atype} — banned type"

        hours = int(args.get("duration_hours", 1))
        if hours < 1 or hours > self.limits.max_suppress_hours:
            return False, (
                f"duration_hours must be in [1, {self.limits.max_suppress_hours}]"
            )

        recent = _count_recent_successful(
            self.audit_db_path, "suppress_alert_type", time.time() - 3600
        )
        if recent >= self.limits.max_suppress_changes_per_hour:
            return False, (
                f"suppress rate cap hit: "
                f"{recent}/{self.limits.max_suppress_changes_per_hour} per hour"
            )
        return True, ""

    def check_unsuppress(self, args: dict) -> tuple[bool, str]:
        try:
            _validate_alert_type(args.get("alert_type"))
        except (ValueError, KeyError) as exc:
            return False, str(exc)
        return True, ""

    # ----- scan -----

    def check_scan(self, args: dict) -> tuple[bool, str]:
        try:
            _validate_target_ip(args.get("ip"))
        except (ValueError, KeyError) as exc:
            return False, f"invalid ip: {exc}"

        scan_type = str(args.get("scan_type") or "").lower()
        if scan_type not in self.limits.allowed_scan_types:
            return False, (
                f"scan_type must be one of {sorted(self.limits.allowed_scan_types)}"
            )

        recent = _count_recent_successful(
            self.audit_db_path, "run_active_scan", time.time() - 3600
        )
        if recent >= self.limits.max_scans_per_hour:
            return False, (
                f"scan rate cap hit: {recent}/{self.limits.max_scans_per_hour} per hour"
            )
        return True, ""

    # ----- notify -----

    def check_notify(self, args: dict) -> tuple[bool, str]:
        sev = str(args.get("severity") or "").upper()
        if sev not in self.limits.allowed_notify_severities:
            return False, (
                f"severity must be one of {sorted(self.limits.allowed_notify_severities)}"
            )
        headline = str(args.get("headline") or "")
        if len(headline) > self.limits.max_headline_chars:
            return False, (
                f"headline must be ≤ {self.limits.max_headline_chars} chars "
                f"(got {len(headline)})"
            )
        recent = _count_recent_successful(
            self.audit_db_path, "send_ntfy_alert", time.time() - 86400
        )
        if recent >= self.limits.max_notifications_per_day:
            return False, (
                f"notification rate cap hit: "
                f"{recent}/{self.limits.max_notifications_per_day} per day"
            )
        return True, ""

    # ----- helpers -----

    def _has_recent_critical(self, ip: str) -> bool:
        try:
            conn = sqlite3.connect(self.events_db_path)
            try:
                cutoff = time.time() - self.limits.critical_event_lookback_hours * 3600
                cur = conn.execute(
                    "SELECT 1 FROM events "
                    "WHERE level = 'CRITICAL' AND timestamp >= ? "
                    "AND (src_ip = ? OR dst_ip = ?) LIMIT 1",
                    (cutoff, ip, ip),
                )
                return cur.fetchone() is not None
            finally:
                conn.close()
        except sqlite3.OperationalError:
            return False  # no events DB → nothing to block on
