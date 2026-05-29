"""Alert handler that opens an incident case with forensic evidence.

On an alert at/above ``min_level`` (with a per-IP cooldown) it:
  1. writes an incident row immediately so it shows in /incidents.html,
  2. runs a short-burst pcap capture of the offending IP,
  3. enriches external IPs against GreyNoise / AbuseIPDB / VirusTotal + GeoIP,
  4. folds the artifacts back into the incident row.

Capture + enrichment run in a thread executor so the asyncio alert pipeline
is never blocked. All steps are best-effort: a failure is logged and the
incident still records whatever did succeed.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time

from ..config import ForensicsConfig
from ..enrich.reputation import enrich_ip
from ..forensics.capture import capture_ip
from ..forensics.store import Incident, IncidentStore
from ..models import Alert, ThreatLevel
from .base import AlertHandler

log = logging.getLogger("netwatchm.forensic_handler")


def _is_external(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local)
    except ValueError:
        return False


class ForensicHandler(AlertHandler):
    def __init__(self, config: ForensicsConfig, interface: str = "") -> None:
        self._config = config
        self._enabled = config.enabled
        self._min_level = ThreatLevel[config.min_level]
        self._iface = (
            interface if config.capture_interface == "auto" else config.capture_interface
        )
        # geoip_db is read by enrich_ip via getattr; reuse the deep-inspect default.
        if not getattr(config, "geoip_db", ""):
            config.geoip_db = "/var/lib/netwatchm/GeoLite2-City.mmdb"  # type: ignore[attr-defined]
        self._cooldown: dict[str, float] = {}  # ip -> last case epoch
        self._store: IncidentStore | None = None
        if self._enabled:
            try:
                self._store = IncidentStore(
                    config.db_path, retention_days=config.retention_days
                ).open()
            except Exception as exc:  # noqa: BLE001
                log.warning("ForensicHandler: cannot open incident store: %s", exc)
                self._enabled = False

    async def send(self, alert: Alert) -> None:
        if not self._enabled or self._store is None:
            return
        if alert.level < self._min_level:
            return

        target = self._pick_target(alert)
        if not target:
            return

        now = time.time()
        last = self._cooldown.get(target, 0.0)
        if now - last < self._config.cooldown_seconds:
            return
        self._cooldown[target] = now

        incident = Incident(
            alert_type=alert.alert_type,
            level=alert.level.name,
            src_ip=alert.src_ip or "",
            dst_ip=alert.dst_ip or "",
            description=alert.description,
        )
        try:
            incident_id = self._store.insert(incident)
        except Exception as exc:  # noqa: BLE001
            log.warning("ForensicHandler: incident insert failed: %s", exc)
            return

        # Heavy work (subprocess + HTTP) off the event loop.
        asyncio.create_task(self._collect(incident_id, target))

    def _pick_target(self, alert: Alert) -> str:
        """Prefer the external IP; fall back to src_ip for scan/brute cases."""
        if _is_external(alert.dst_ip):
            return alert.dst_ip  # type: ignore[return-value]
        if _is_external(alert.src_ip):
            return alert.src_ip  # type: ignore[return-value]
        return alert.src_ip or alert.dst_ip or ""

    async def _collect(self, incident_id: int, target: str) -> None:
        loop = asyncio.get_event_loop()
        pcap_path, pcap_bytes = "", 0
        if self._config.capture_enabled and self._iface:
            try:
                pcap_path, pcap_bytes = await loop.run_in_executor(
                    None, capture_ip, target, self._iface,
                    self._config.capture_seconds, self._config.capture_dir,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("ForensicHandler: capture error for %s: %s", target, exc)

        verdict, score, summary, intel_json = "unknown", 0, "", "{}"
        try:
            rep = await loop.run_in_executor(None, enrich_ip, target, self._config)
            verdict, score, summary = rep.verdict, rep.score, rep.summary
            intel_json = json.dumps(rep.to_dict())
        except Exception as exc:  # noqa: BLE001
            log.warning("ForensicHandler: enrichment error for %s: %s", target, exc)

        try:
            self._store.update_artifacts(
                incident_id, verdict=verdict, score=score, intel_summary=summary,
                intel_json=intel_json, pcap_path=pcap_path, pcap_bytes=pcap_bytes,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("ForensicHandler: artifact update failed: %s", exc)
