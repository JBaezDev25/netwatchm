"""Build the snapshot fed to the LLM each decision tick.

Critical safety property: every string that originates from observed network
traffic (DNS query names, SNI strings, alert descriptions) is sanitized
through ``_safe()`` before it reaches the prompt. Attacker-controllable text
is wrapped in <untrusted> tags and length-capped, so a malicious payload like
``dns_query="; ignore previous instructions"`` cannot inject commands into
the agent's reasoning.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_MAX_FIELD_LEN = 200


def _safe(s: Any, *, max_len: int = _MAX_FIELD_LEN) -> str:
    """Sanitize any string that may have originated from observed traffic.

    Removes control characters, ASCII-strips, truncates, and is intended to be
    wrapped in <untrusted> tags by the caller when embedded in prompt text.
    """
    if s is None:
        return ""
    text = str(s)
    text = _CONTROL_CHARS.sub("", text)
    # Strip the tag delimiters defensively so the wrapper can't be escaped.
    text = text.replace("<untrusted>", "").replace("</untrusted>", "")
    if len(text) > max_len:
        text = text[:max_len] + "…"
    return text


def _data_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "netwatchm"
    return Path("/var/lib/netwatchm")


def _read_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text())
    except Exception:  # noqa: BLE001
        pass
    return default


def build_context(
    *,
    events_db_path: str,
    config_snapshot: dict,
    hours_back: int = 4,
    max_events: int = 50,
    data_dir: str | None = None,
) -> dict:
    """Build a single decision-tick snapshot for the LLM.

    Returns a dict with keys: meta, recent_events, inventory_summary,
    policy, threat_summary. All packet-derived strings are pre-sanitized.

    ``data_dir`` overrides the default platform data directory (used by tests
    and by callers that have configured a non-default inventory location).
    """
    import sqlite3  # local — keep module import-light

    dd = Path(data_dir) if data_dir else _data_dir()
    aliases = _read_json(dd / "aliases.json", {})
    verified = _read_json(dd / "verified.json", {})
    suppressed_types = list(
        _read_json(dd / "suppressed.json", {"types": []}).get("types", [])
    )
    inventory_raw = _read_json(dd / "inventory.json", {})

    # inventory.json may be a dict {ip: record} or a list [record, ...]
    # depending on which serialiser wrote it. Normalise to dict.
    if isinstance(inventory_raw, list):
        inventory_raw = {
            (rec.get("ip") if isinstance(rec, dict) else None) or str(i): rec
            for i, rec in enumerate(inventory_raw)
        }
    elif not isinstance(inventory_raw, dict):
        inventory_raw = {}

    cutoff = time.time() - hours_back * 3600
    recent_events: list[dict] = []
    severity_count: dict[str, int] = {}
    max_severity: str | None = None

    if Path(events_db_path).exists():
        conn = sqlite3.connect(events_db_path)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(
                "SELECT timestamp, alert_type, level, src_ip, dst_ip, description "
                "FROM events WHERE timestamp >= ? "
                "ORDER BY timestamp DESC LIMIT ?",
                (cutoff, max_events),
            )
            rows = [dict(r) for r in cur.fetchall()]
            cur = conn.execute(
                "SELECT level, COUNT(*) as n FROM events WHERE timestamp >= ? GROUP BY level",
                (cutoff,),
            )
            severity_count = {r["level"]: r["n"] for r in cur.fetchall()}
        finally:
            conn.close()

        for r in rows:
            recent_events.append(
                {
                    "ts": r["timestamp"],
                    "alert_type": _safe(r["alert_type"], max_len=40),
                    "level": _safe(r["level"], max_len=20),
                    "src_ip": _safe(r["src_ip"], max_len=64),
                    "dst_ip": _safe(r["dst_ip"], max_len=64),
                    # description is the most attacker-controllable field
                    "untrusted_description": f"<untrusted>{_safe(r['description'])}</untrusted>",
                }
            )

    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if severity_count:
        max_severity = max(severity_count.keys(), key=lambda k: rank.get(k, 0))

    devices_summary: list[dict] = []
    for ip, dev in sorted(inventory_raw.items())[:100]:
        if not isinstance(dev, dict):
            continue
        devices_summary.append(
            {
                "ip": _safe(ip, max_len=64),
                "hostname": _safe(dev.get("hostname"), max_len=80),
                "vendor": _safe(dev.get("vendor"), max_len=80),
                "alias": _safe(aliases.get(ip), max_len=80),
                "verified": bool(verified.get(ip, False)),
                "threat_level": _safe(dev.get("threat_level"), max_len=20),
                "last_seen": dev.get("last_seen"),
            }
        )

    return {
        "meta": {
            "generated_at": time.time(),
            "hours_back": hours_back,
            "device_count": len(devices_summary),
            "event_count": len(recent_events),
        },
        "threat_summary": {
            "max_severity": max_severity,
            "by_level": severity_count,
        },
        "recent_events": recent_events,
        "inventory_summary": devices_summary,
        "policy": {
            "whitelist_ips": list(config_snapshot.get("whitelist_ips", [])),
            "detector_whitelist": dict(config_snapshot.get("detector_whitelist", {})),
            "suppressed_alert_types": suppressed_types,
        },
    }
