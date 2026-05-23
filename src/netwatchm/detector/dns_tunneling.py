"""DNS tunneling detector: HIGH alert on bursts of long / high-entropy DNS queries."""
from __future__ import annotations

import math
import time
from collections import defaultdict, deque

from ..config import DnsTunnelingConfig
from ..models import Alert, Packet, ThreatLevel
from .base import Detector


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class DnsTunnelingDetector(Detector):
    """Detect DNS tunneling: bursts of long or high-entropy DNS queries.

    A query is suspicious when ANY of these is true:
      • full FQDN length >= ``min_query_length``
      • leftmost label length >= ``min_label_length``
      • leftmost label Shannon entropy >= ``entropy_threshold`` AND
        leftmost label length > 12

    HIGH alert fires when one src_ip emits ``queries_per_window`` suspicious
    queries within ``window_seconds``.
    """

    def __init__(self, config: DnsTunnelingConfig) -> None:
        self._config = config
        self._suspicious: dict[str, deque[float]] = defaultdict(deque)
        self._alerted: dict[str, float] = {}
        self._last_query: dict[str, str] = {}

    def _is_suspicious(self, query: str) -> bool:
        cfg = self._config
        if len(query) >= cfg.min_query_length:
            return True
        label = query.split(".", 1)[0]
        if len(label) >= cfg.min_label_length:
            return True
        if len(label) > 12 and _shannon_entropy(label) >= cfg.entropy_threshold:
            return True
        return False

    def process(self, packet: Packet) -> Alert | None:
        if not self._config.enabled or not packet.dns_query or not packet.src_ip:
            return None

        query = packet.dns_query.rstrip(".")
        if not self._is_suspicious(query):
            return None

        now = time.time()
        dq = self._suspicious[packet.src_ip]
        dq.append(now)
        cutoff = now - self._config.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()
        self._last_query[packet.src_ip] = query

        if len(dq) < self._config.queries_per_window:
            return None

        last = self._alerted.get(packet.src_ip, 0.0)
        if now - last < self._config.alert_window_seconds:
            return None
        self._alerted[packet.src_ip] = now

        sample = query if len(query) <= 80 else query[:77] + "..."
        return Alert(
            alert_type="DNS_TUNNELING",
            level=ThreatLevel.HIGH,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            description=(
                f"Possible DNS tunneling from {packet.src_ip}: "
                f"{len(dq)} suspicious queries in {self._config.window_seconds}s "
                f"(latest: {sample})"
            ),
        )

    def flush_expired(self) -> None:
        now = time.time()
        cutoff = now - self._config.window_seconds
        for ip in list(self._suspicious.keys()):
            dq = self._suspicious[ip]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del self._suspicious[ip]
                self._last_query.pop(ip, None)

        alert_cutoff = now - self._config.alert_window_seconds
        expired = [ip for ip, t in self._alerted.items() if t < alert_cutoff]
        for ip in expired:
            del self._alerted[ip]
