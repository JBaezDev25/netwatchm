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
import logging
import shutil
import sqlite3
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("netwatchm.agent.guardrails")


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
    # Phase 5 — firewall block caps
    max_block_changes_per_hour: int = 5
    max_active_blocks: int = 10
    max_block_minutes: int = 1440           # 24 h hard cap on a single rule
    default_block_minutes: int = 60         # 1 h default if LLM doesn't specify
    # Ports the agent must never touch (in either direction) so SSH admin
    # cannot be locked out by a misguided rule. Stored as int set for fast
    # membership testing.
    banned_block_ports: frozenset[int] = field(
        default_factory=lambda: frozenset({22})
    )
    # Protocols ufw accepts; everything else refused at validation time.
    allowed_block_protocols: frozenset[str] = field(
        default_factory=lambda: frozenset({"tcp", "udp"})
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


# ---------- Host network discovery (for firewall guardrails) ----------


def _ip_route_default_gateways() -> list[str]:
    """Parse ``ip route show default`` for default gateway IPs. Empty
    list on any failure — guardrails treat missing data as "no gateway
    to protect" which is the safe default in tests."""
    ip_bin = shutil.which("ip")
    if not ip_bin:
        return []
    try:
        cp = subprocess.run(
            [ip_bin, "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.warning("ip route lookup failed: %s", exc)
        return []
    gateways: list[str] = []
    for line in (cp.stdout or "").splitlines():
        # Lines look like:  default via 192.168.1.1 dev eth0 ...
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "default" and parts[1] == "via":
            try:
                ipaddress.ip_address(parts[2])
                gateways.append(parts[2])
            except ValueError:
                continue
    return gateways


def _ip_addr_host_ips() -> list[str]:
    """Return all globally-routable + private IPv4/IPv6 host IPs. We do
    NOT include link-local addresses — those are auto-blocked by the
    RFC1918/link-local refusal in :meth:`Guardrails.check_block`."""
    ip_bin = shutil.which("ip")
    if not ip_bin:
        return []
    try:
        cp = subprocess.run(
            [ip_bin, "-o", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.warning("ip addr lookup failed: %s", exc)
        return []
    ips: list[str] = []
    for line in (cp.stdout or "").splitlines():
        # Each line like:  2: eth0    inet 192.168.1.180/24 brd ...
        parts = line.split()
        try:
            family_idx = parts.index("inet")
        except ValueError:
            try:
                family_idx = parts.index("inet6")
            except ValueError:
                continue
        if family_idx + 1 >= len(parts):
            continue
        cidr = parts[family_idx + 1]
        ip_only = cidr.split("/", 1)[0]
        try:
            addr = ipaddress.ip_address(ip_only)
        except ValueError:
            continue
        if addr.is_link_local:
            continue
        ips.append(ip_only)
    return ips


def detect_host_network_info() -> tuple[list[str], list[str]]:
    """Return ``(gateway_ips, host_ips)`` for the running host. Safe to
    call at startup; both lists may be empty if ``ip`` is missing or
    times out."""
    return _ip_route_default_gateways(), _ip_addr_host_ips()


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
        firewall_store: Any | None = None,
        global_whitelist_ips: list[str] | None = None,
        gateway_ips: list[str] | None = None,
        host_ips: list[str] | None = None,
    ) -> None:
        self.audit_db_path = audit_db_path
        self.events_db_path = events_db_path
        self.limits = limits or GuardrailLimits()
        # Firewall context — None / empty is fine; the check_block call will
        # still enforce the RFC1918 and structural rules even without these.
        self.firewall_store = firewall_store
        self.global_whitelist_ips = frozenset(global_whitelist_ips or [])
        self.gateway_ips = frozenset(gateway_ips or [])
        self.host_ips = frozenset(host_ips or [])

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

    # ----- firewall block (Phase 5) -----

    def check_block(self, args: dict) -> tuple[bool, str]:
        """Validate an ``add_temporary_block`` request.

        Refuses, in this order, the first failing condition:

        - malformed IP literal (or CIDR — only single literals accepted)
        - IP unspecified / multicast / reserved
        - IP in RFC1918 (10/8, 172.16/12, 192.168/16) — never block internal
        - IP == any gateway / host-local IP — never self-block
        - IP in the global whitelist — explicit allow wins
        - port 22 in any direction (or any port in ``banned_block_ports``)
        - port out of range 1..65535 (when present)
        - protocol not in {tcp, udp} (when present)
        - ``duration_minutes`` outside [1, ``max_block_minutes``]
        - ``reason`` empty or whitespace
        - active blocks ≥ ``max_active_blocks``
        - hourly add+remove rate ≥ ``max_block_changes_per_hour``
        """
        # IP shape
        try:
            addr = _validate_target_ip(args.get("ip"))
        except (ValueError, KeyError) as exc:
            return False, f"invalid ip: {exc}"

        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return (
                False,
                f"refusing to block {addr} — internal/loopback/link-local IPs are off-limits",
            )

        ip_s = str(addr)
        if ip_s in self.gateway_ips:
            return False, f"refusing to block gateway {ip_s}"
        if ip_s in self.host_ips:
            return False, f"refusing to block our own host IP {ip_s}"
        if ip_s in self.global_whitelist_ips:
            return False, f"refusing to block whitelisted IP {ip_s}"

        # Port
        port = args.get("port")
        if port is not None:
            try:
                port_n = int(port)
            except (TypeError, ValueError):
                return False, f"invalid port: {port!r}"
            if not (1 <= port_n <= 65535):
                return False, f"port {port_n} out of range 1..65535"
            if port_n in self.limits.banned_block_ports:
                return False, (
                    f"refusing to touch port {port_n} (banned to prevent admin lockout)"
                )

        # Protocol
        proto = args.get("protocol")
        if proto is not None:
            proto_s = str(proto).strip().lower()
            if proto_s not in self.limits.allowed_block_protocols:
                return False, (
                    f"protocol {proto_s!r} not allowed; must be one of "
                    f"{sorted(self.limits.allowed_block_protocols)}"
                )

        # Duration
        duration = int(args.get("duration_minutes", self.limits.default_block_minutes))
        if duration < 1 or duration > self.limits.max_block_minutes:
            return False, (
                f"duration_minutes must be in [1, {self.limits.max_block_minutes}]"
            )

        # Reason (mandatory + non-empty so the audit trail isn't useless)
        reason = str(args.get("reason") or "").strip()
        if not reason:
            return False, "reason is required and must not be empty"

        # Active-block ceiling
        if self.firewall_store is not None:
            active = self.firewall_store.count_active()
            if active >= self.limits.max_active_blocks:
                return False, (
                    f"refusing — {active} active blocks already "
                    f"(ceiling = {self.limits.max_active_blocks})"
                )

        # Hourly rate cap (add+remove combined, like whitelist)
        recent = _count_recent_successful(
            self.audit_db_path, "add_temporary_block", time.time() - 3600
        ) + _count_recent_successful(
            self.audit_db_path, "remove_block", time.time() - 3600
        )
        if recent >= self.limits.max_block_changes_per_hour:
            return False, (
                f"block rate cap hit: "
                f"{recent}/{self.limits.max_block_changes_per_hour} per hour"
            )

        return True, ""

    def check_remove_block(self, args: dict) -> tuple[bool, str]:
        """Validate a ``remove_block`` request. Same rate cap as add; IP
        must still parse but RFC1918 etc. are allowed (so we can clean up
        a rule that was added before the guard was tightened)."""
        try:
            _validate_target_ip(args.get("ip"))
        except (ValueError, KeyError) as exc:
            return False, f"invalid ip: {exc}"

        port = args.get("port")
        if port is not None:
            try:
                port_n = int(port)
            except (TypeError, ValueError):
                return False, f"invalid port: {port!r}"
            if not (1 <= port_n <= 65535):
                return False, f"port {port_n} out of range 1..65535"

        recent = _count_recent_successful(
            self.audit_db_path, "add_temporary_block", time.time() - 3600
        ) + _count_recent_successful(
            self.audit_db_path, "remove_block", time.time() - 3600
        )
        if recent >= self.limits.max_block_changes_per_hour:
            return False, (
                f"block rate cap hit: "
                f"{recent}/{self.limits.max_block_changes_per_hour} per hour"
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
