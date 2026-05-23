"""Tool definitions exposed to the LLM.

Phase 1 ships read-only context tools only. Phase 2 adds action tools
(whitelist mutation, scans, notifications), which will route through
``executor.py`` and ``guardrails.py``.

Each tool has:
  - a JSON schema (OpenAI/Ollama tool-calling format)
  - a Python implementation taking ``args: dict`` → ``dict``

The dispatcher (``run_tool``) validates the tool name and rejects unknown
calls. Argument validation is per-tool; any ValueError raised by an
implementation surfaces as a structured ``error`` in the result.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("netwatchm.agent.tools")


# ---------- Argument validators ----------


def _require_ip(value: Any) -> str:
    """Validate that value is a syntactically-valid IPv4/IPv6 literal.

    Defense against tool-call argument injection. We refuse anything that
    doesn't parse as an IP — no shell metacharacters can ride through here.
    """
    s = str(value).strip()
    ipaddress.ip_address(s)  # raises ValueError on bad input
    return s


def _require_int(value: Any, lo: int, hi: int) -> int:
    n = int(value)
    if not (lo <= n <= hi):
        raise ValueError(f"value {n} out of range [{lo}, {hi}]")
    return n


# ---------- Read-only tool implementations ----------


def _tool_query_recent_events(
    args: dict,
    *,
    events_db_path: str,
) -> dict:
    hours = _require_int(args.get("hours", 24), 1, 168)
    limit = _require_int(args.get("limit", 50), 1, 500)
    level = args.get("level")
    if level is not None and level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise ValueError(f"invalid level: {level}")

    if not Path(events_db_path).exists():
        return {"events": []}

    cutoff = time.time() - hours * 3600
    conn = sqlite3.connect(events_db_path)
    conn.row_factory = sqlite3.Row
    try:
        clauses = ["timestamp >= ?"]
        params: list[Any] = [cutoff]
        if level:
            clauses.append("level = ?")
            params.append(level)
        params.append(limit)
        cur = conn.execute(
            f"SELECT timestamp, alert_type, level, src_ip, dst_ip, description "
            f"FROM events WHERE {' AND '.join(clauses)} "
            f"ORDER BY timestamp DESC LIMIT ?",
            params,
        )
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return {"events": rows, "count": len(rows)}


def _tool_query_threat_history(
    args: dict,
    *,
    events_db_path: str,
) -> dict:
    ip = _require_ip(args["ip"])
    hours = _require_int(args.get("hours", 168), 1, 720)  # up to 30 days

    if not Path(events_db_path).exists():
        return {"ip": ip, "events": []}

    cutoff = time.time() - hours * 3600
    conn = sqlite3.connect(events_db_path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(
            "SELECT alert_type, level, COUNT(*) as n, MAX(timestamp) as last_ts "
            "FROM events WHERE timestamp >= ? AND (src_ip = ? OR dst_ip = ?) "
            "GROUP BY alert_type, level ORDER BY n DESC",
            (cutoff, ip, ip),
        )
        breakdown = [dict(r) for r in cur.fetchall()]
        cur = conn.execute(
            "SELECT timestamp, alert_type, level, description "
            "FROM events WHERE timestamp >= ? AND (src_ip = ? OR dst_ip = ?) "
            "ORDER BY timestamp DESC LIMIT 20",
            (cutoff, ip, ip),
        )
        recent = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return {"ip": ip, "breakdown": breakdown, "recent": recent}


def _tool_query_device_inventory(args: dict, *, inventory_path: str) -> dict:
    ip_filter = args.get("ip")
    if ip_filter:
        ip_filter = _require_ip(ip_filter)
    inv = {}
    p = Path(inventory_path)
    if p.exists():
        try:
            inv = json.loads(p.read_text())
        except Exception:  # noqa: BLE001
            inv = {}
    if ip_filter:
        dev = inv.get(ip_filter) if isinstance(inv, dict) else None
        return {"ip": ip_filter, "device": dev}
    if not isinstance(inv, dict):
        return {"devices": []}
    return {"devices": list(inv.values())[:200], "total": len(inv)}


def _tool_query_whitelist_state(args: dict, *, config_snapshot: dict) -> dict:
    return {
        "global_whitelist": list(config_snapshot.get("whitelist_ips", [])),
        "detector_whitelist": dict(config_snapshot.get("detector_whitelist", {})),
    }


def _tool_query_suppression_state(args: dict, *, data_dir: str) -> dict:
    p = Path(data_dir) / "suppressed.json"
    if not p.exists():
        return {"suppressed_types": []}
    try:
        body = json.loads(p.read_text())
        return {"suppressed_types": list(body.get("types", []))}
    except Exception:  # noqa: BLE001
        return {"suppressed_types": []}


# ---------- Tool schemas (OpenAI/Ollama tool-calling format) ----------


ACTION_TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "add_whitelist_entry",
            "description": (
                "Add an IP to the agent-managed whitelist so its alerts are "
                "suppressed for ttl_hours. Use only after confirming the IP "
                "is benign (e.g. cross-checked threat history + known service). "
                "TTL forces the entry to expire — re-add if still valid later."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IPv4/IPv6 literal"},
                    "scope": {
                        "type": "string",
                        "enum": ["global", "detector"],
                        "description": "global = suppress all alerts; detector = one alert_type",
                    },
                    "alert_type": {
                        "type": "string",
                        "description": "Required when scope=detector",
                    },
                    "ttl_hours": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 72,
                        "default": 24,
                    },
                    "reason": {"type": "string", "description": "One-sentence rationale"},
                },
                "required": ["ip", "scope", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "remove_whitelist_entry",
            "description": (
                "Roll back an agent whitelist entry by (ip, scope, alert_type). "
                "Use this if you decide a previously-whitelisted IP is actually "
                "suspicious."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string"},
                    "scope": {"type": "string", "enum": ["global", "detector"]},
                    "alert_type": {"type": "string"},
                },
                "required": ["ip", "scope"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "suppress_alert_type",
            "description": (
                "Temporarily silence an alert type across all devices. Use "
                "sparingly — refuses CRITICAL types. Capped at 24h duration."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "alert_type": {"type": "string"},
                    "duration_hours": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 24,
                        "default": 1,
                    },
                    "reason": {"type": "string"},
                },
                "required": ["alert_type", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "unsuppress_alert_type",
            "description": "Re-enable an alert type that was previously suppressed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "alert_type": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["alert_type", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_active_scan",
            "description": (
                "Actively probe a target IP. Use after a HIGH alert to gather "
                "evidence. Rate-capped at 10/hour."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string"},
                    "scan_type": {
                        "type": "string",
                        "enum": ["nmap_ports", "deep_inspect"],
                    },
                    "reason": {"type": "string"},
                },
                "required": ["ip", "scan_type", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_ntfy_alert",
            "description": (
                "Push a notification to the user's phone via ntfy. Include "
                "rollback_entry_id if this notification announces a whitelist "
                "addition the user might want to reverse. Rate-capped at "
                "20/day."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    },
                    "headline": {
                        "type": "string",
                        "description": "≤ 200 chars — shown as the ntfy title",
                    },
                    "action_taken": {
                        "type": "string",
                        "description": "One short sentence describing what the agent did",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Why the agent acted",
                    },
                    "related_ip": {"type": "string"},
                    "rollback_entry_id": {
                        "type": "string",
                        "description": (
                            "Whitelist entry UUID returned by "
                            "add_whitelist_entry — enables the Rollback action button"
                        ),
                    },
                    "unblock_entry_id": {
                        "type": "string",
                        "description": (
                            "Firewall block entry UUID returned by "
                            "add_temporary_block — enables the Unblock action button"
                        ),
                    },
                },
                "required": ["severity", "headline", "action_taken", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_temporary_block",
            "description": (
                "Drop incoming traffic from one external IP via ufw. Auto-expires "
                "after duration_minutes (default 60, max 1440). Refuses RFC1918, "
                "loopback, the gateway, our own host IPs, the global whitelist, "
                "and port 22 in any direction. Active-block ceiling of 10 and "
                "rate cap of 5/hour. ALWAYS investigate first — call "
                "query_threat_history before blocking. Pair with send_ntfy_alert "
                "(use unblock_entry_id) so the user gets a one-tap Unblock."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "Public IPv4/IPv6 literal"},
                    "port": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 65535,
                        "description": "Optional: limit block to one port. Omit to block all ports.",
                    },
                    "protocol": {
                        "type": "string",
                        "enum": ["tcp", "udp"],
                        "description": "Optional: limit block to one protocol.",
                    },
                    "duration_minutes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 1440,
                        "default": 60,
                    },
                    "reason": {
                        "type": "string",
                        "description": "Required, non-empty. One-sentence justification.",
                    },
                },
                "required": ["ip", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "remove_block",
            "description": (
                "Remove a firewall block (regardless of TTL). Use when a block "
                "turns out to be a false positive."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string"},
                    "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                },
                "required": ["ip"],
            },
        },
    },
]


TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "query_recent_events",
            "description": (
                "Return network alert events from the last N hours. Use to "
                "understand current threat activity. Filter by severity if needed."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "hours": {"type": "integer", "minimum": 1, "maximum": 168, "default": 24},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
                    "level": {
                        "type": "string",
                        "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        "description": "Optional severity filter",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_threat_history",
            "description": (
                "Get historical alert breakdown for a specific IP — how often "
                "it has fired alerts and at what severities."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IPv4/IPv6 address"},
                    "hours": {"type": "integer", "minimum": 1, "maximum": 720, "default": 168},
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_device_inventory",
            "description": (
                "Look up device inventory data (hostname, MAC, vendor, bytes, "
                "last_seen). Pass an IP for one device, or omit to list all."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "Optional IPv4/IPv6"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_whitelist_state",
            "description": "Return current global + per-detector whitelist configuration.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_suppression_state",
            "description": "Return alert types currently suppressed across all devices.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]


# ---------- Dispatcher ----------


def run_tool(
    tool_name: str,
    args: dict,
    *,
    events_db_path: str,
    inventory_path: str,
    config_snapshot: dict,
    data_dir: str,
) -> dict:
    """Execute a tool by name. Returns ``{"ok": True, "data": ...}`` on
    success or ``{"ok": False, "error": "..."}`` on validation/execution failure."""
    impls: dict[str, Callable[..., dict]] = {
        "query_recent_events": lambda a: _tool_query_recent_events(
            a, events_db_path=events_db_path
        ),
        "query_threat_history": lambda a: _tool_query_threat_history(
            a, events_db_path=events_db_path
        ),
        "query_device_inventory": lambda a: _tool_query_device_inventory(
            a, inventory_path=inventory_path
        ),
        "query_whitelist_state": lambda a: _tool_query_whitelist_state(
            a, config_snapshot=config_snapshot
        ),
        "query_suppression_state": lambda a: _tool_query_suppression_state(
            a, data_dir=data_dir
        ),
    }
    fn = impls.get(tool_name)
    if fn is None:
        return {"ok": False, "error": f"unknown tool: {tool_name}"}
    try:
        return {"ok": True, "data": fn(args or {})}
    except (ValueError, KeyError) as exc:
        return {"ok": False, "error": f"bad args: {exc}"}
    except Exception as exc:  # noqa: BLE001
        logger.exception("tool %s failed", tool_name)
        return {"ok": False, "error": f"execution error: {exc}"}
