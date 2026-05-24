"""Periodic threat digest.

Instead of pushing a notification on every alert, the agent (in ``mode:
digest``) emits ONE categorized summary every ``digest_interval_days``. This
module does the deterministic half: it aggregates the event store by category
over the lookback window (so counts are always exact, never hallucinated) and
provides the ntfy push helper. The LLM only writes the prose + mitigations
around these numbers — see ``agent_loop._run_digest_tick``.

Beacon patterns (and anything in ``exclude_types``) are dropped here so they
never reach the digest or the notification.
"""
from __future__ import annotations

import logging
import time
import urllib.request
from pathlib import Path
from urllib.error import URLError

from .context import _safe

logger = logging.getLogger("netwatchm.agent")

_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_TOP_SOURCES = 5


def build_digest(
    *,
    events_db_path: str,
    lookback_days: int = 5,
    exclude_types: list[str] | None = None,
    max_events: int = 2000,
) -> dict:
    """Aggregate the event store by alert category over the lookback window.

    Returns a dict with ``window`` metadata and a ``categories`` list, each
    entry holding exact counts, distinct/top source IPs, the worst severity
    seen, and the most recent timestamp. All source IPs are sanitized.
    """
    import sqlite3  # local — keep module import-light

    # None → default to excluding beacons; an explicit [] includes everything.
    if exclude_types is None:
        exclude_types = ["BEACONING"]
    excluded = {t.upper() for t in exclude_types}
    cutoff = time.time() - lookback_days * 86400
    cats: dict[str, dict] = {}
    total = 0
    excluded_count = 0

    if Path(events_db_path).exists():
        conn = sqlite3.connect(events_db_path)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(
                "SELECT timestamp, alert_type, level, src_ip "
                "FROM events WHERE timestamp >= ? "
                "ORDER BY timestamp DESC LIMIT ?",
                (cutoff, max_events),
            )
            rows = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

        for r in rows:
            atype = (r["alert_type"] or "UNKNOWN").upper()
            if atype in excluded:
                excluded_count += 1
                continue
            total += 1
            c = cats.setdefault(
                atype,
                {
                    "alert_type": atype,
                    "count": 0,
                    "sources": {},   # ip -> hits
                    "max_level": "LOW",
                    "last_seen": 0.0,
                },
            )
            c["count"] += 1
            src = _safe(r["src_ip"], max_len=64) or "(none)"
            c["sources"][src] = c["sources"].get(src, 0) + 1
            lvl = (r["level"] or "LOW").upper()
            if _RANK.get(lvl, 0) > _RANK.get(c["max_level"], 0):
                c["max_level"] = lvl
            if r["timestamp"] and r["timestamp"] > c["last_seen"]:
                c["last_seen"] = r["timestamp"]

    categories = []
    for c in cats.values():
        top = sorted(c["sources"].items(), key=lambda kv: kv[1], reverse=True)
        categories.append(
            {
                "alert_type": c["alert_type"],
                "count": c["count"],
                "max_level": c["max_level"],
                "distinct_sources": len(c["sources"]),
                "top_sources": [{"ip": ip, "hits": n} for ip, n in top[:_TOP_SOURCES]],
                "last_seen": c["last_seen"],
            }
        )
    # worst-first so the prompt and the human read the scary stuff first
    categories.sort(key=lambda c: (_RANK.get(c["max_level"], 0), c["count"]), reverse=True)

    return {
        "window": {
            "lookback_days": lookback_days,
            "generated_at": time.time(),
            "total_events": total,
            "excluded_events": excluded_count,
            "excluded_types": sorted(excluded),
            "category_count": len(categories),
        },
        "categories": categories,
    }


def render_fallback(digest: dict) -> str:
    """Plain-text digest used if the LLM call fails — never leave the user blank."""
    w = digest["window"]
    lines = [
        f"NetWatchM digest — last {w['lookback_days']}d",
        f"{w['total_events']} events across {w['category_count']} categories.",
        "",
    ]
    for c in digest["categories"]:
        top = c["top_sources"][0]["ip"] if c["top_sources"] else "n/a"
        lines.append(
            f"[{c['max_level']}] {c['alert_type']}: {c['count']} "
            f"({c['distinct_sources']} src, top {top})"
        )
    if not digest["categories"]:
        lines.append("No threats in window. Quiet period.")
    return "\n".join(lines)


def push_digest(ntfy_cfg, title: str, body: str) -> bool:
    """POST the digest to ntfy. Returns True on success.

    Uses the same NtfyAlertConfig (server/topic/token) as real-time alerts,
    but bypasses the per-type cooldown/min-level filtering — a digest always
    goes out. Priority is fixed at 3 (default) since it is a summary, not a
    live threat.
    """
    if not getattr(ntfy_cfg, "topic", ""):
        logger.warning("digest: ntfy topic not configured — not pushing")
        return False
    url = f"{ntfy_cfg.server.rstrip('/')}/{ntfy_cfg.topic}"
    headers = {
        "X-Title": title,
        "X-Priority": "3",
        "X-Tags": "netwatchm,digest",
        "Content-Type": "text/plain",
    }
    if getattr(ntfy_cfg, "token", ""):
        headers["Authorization"] = f"Bearer {ntfy_cfg.token}"
    req = urllib.request.Request(
        url, data=body.encode()[:4000], headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            logger.info("digest pushed to ntfy topic=%s", ntfy_cfg.topic)
        return True
    except URLError as exc:
        logger.warning("digest push failed: %s", exc)
    except Exception as exc:  # noqa: BLE001
        logger.warning("digest push unexpected error: %s", exc)
    return False
