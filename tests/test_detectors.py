"""Tests for threat detectors."""
from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from netwatchm.config import (
    BruteForceThreshold,
    ExfiltrationThreshold,
    NewIPThreshold,
    PortScanThreshold,
)
from netwatchm.detector.brute_force import BruteForceDetector
from netwatchm.detector.exfiltration import ExfiltrationDetector
from netwatchm.detector.new_ip import NewIPDetector
from netwatchm.detector.port_scan import PortScanDetector
from netwatchm.models import Packet, ThreatLevel
from .conftest import make_packet


# ──────────────── Port Scan ────────────────

class TestPortScanDetector:
    def _detector(self, ports=5, window=60) -> PortScanDetector:
        return PortScanDetector(PortScanThreshold(ports_per_window=ports, window_seconds=window))

    def test_no_alert_below_threshold(self) -> None:
        det = self._detector(ports=5)
        for port in range(1, 5):
            result = det.process(make_packet(dst_port=port))
            assert result is None

    def test_alert_at_threshold(self) -> None:
        det = self._detector(ports=5)
        alert = None
        for port in range(1, 7):
            result = det.process(make_packet(dst_port=port))
            if result:
                alert = result
        assert alert is not None
        assert alert.alert_type == "PORT_SCAN"
        assert alert.level == ThreatLevel.HIGH

    def test_no_duplicate_alert_same_src(self) -> None:
        """Second alert for same src is suppressed while window active."""
        det = self._detector(ports=3)
        alerts = []
        for port in range(1, 20):
            r = det.process(make_packet(dst_port=port))
            if r:
                alerts.append(r)
        assert len(alerts) == 1

    def test_different_src_ips_independent(self) -> None:
        det = self._detector(ports=3)
        alert1 = None
        alert2 = None
        for port in range(1, 5):
            r = det.process(make_packet(src_ip="1.1.1.1", dst_port=port))
            if r:
                alert1 = r
        for port in range(1, 5):
            r = det.process(make_packet(src_ip="2.2.2.2", dst_port=port))
            if r:
                alert2 = r
        assert alert1 is not None
        assert alert2 is not None

    def test_no_alert_without_dst_port(self) -> None:
        det = self._detector(ports=1)
        result = det.process(make_packet(dst_port=None))
        assert result is None

    def test_flush_expired_clears_state(self) -> None:
        det = self._detector(ports=5, window=1)
        for port in range(1, 6):
            det.process(make_packet(dst_port=port))
        time.sleep(1.1)
        det.flush_expired()
        assert len(det._windows) == 0


# ──────────────── Brute Force ────────────────

class TestBruteForceDetector:
    def _detector(self, attempts=3, window=60) -> BruteForceDetector:
        return BruteForceDetector(
            BruteForceThreshold(attempts_per_window=attempts, window_seconds=window, ports=[22])
        )

    def test_no_alert_non_auth_port(self) -> None:
        det = self._detector()
        for _ in range(10):
            result = det.process(make_packet(dst_port=80))
        assert result is None

    def test_alert_at_threshold(self) -> None:
        det = self._detector(attempts=3)
        alert = None
        for _ in range(4):
            r = det.process(make_packet(dst_port=22))
            if r:
                alert = r
        assert alert is not None
        assert alert.alert_type == "BRUTE_FORCE"
        assert alert.level == ThreatLevel.HIGH

    def test_no_duplicate_alert(self) -> None:
        det = self._detector(attempts=2)
        alerts = [det.process(make_packet(dst_port=22)) for _ in range(10)]
        non_none = [a for a in alerts if a is not None]
        assert len(non_none) == 1

    def test_flush_expired(self) -> None:
        det = self._detector(attempts=2, window=1)
        for _ in range(3):
            det.process(make_packet(dst_port=22))
        time.sleep(1.1)
        det.flush_expired()
        assert len(det._windows) == 0


# ──────────────── Exfiltration ────────────────

class TestExfiltrationDetector:
    def _detector(self, limit=1000, window=60) -> ExfiltrationDetector:
        return ExfiltrationDetector(
            ExfiltrationThreshold(bytes_per_window=limit, window_seconds=window)
        )

    def test_no_alert_internal_traffic(self) -> None:
        det = self._detector(limit=100)
        # Both IPs are local; should not alert
        for _ in range(20):
            result = det.process(make_packet(src_ip="192.168.1.1", dst_ip="192.168.1.2", length=100))
        assert result is None

    def test_alert_outbound_large(self) -> None:
        det = self._detector(limit=500)
        alert = None
        for _ in range(6):
            r = det.process(make_packet(src_ip="192.168.1.1", dst_ip="8.8.8.8", length=100))
            if r:
                alert = r
        assert alert is not None
        assert alert.alert_type == "EXFILTRATION"
        assert alert.level == ThreatLevel.CRITICAL

    def test_no_alert_inbound(self) -> None:
        det = self._detector(limit=100)
        for _ in range(20):
            result = det.process(make_packet(src_ip="8.8.8.8", dst_ip="192.168.1.1", length=100))
        assert result is None


# ──────────────── New IP ────────────────

class TestNewIPDetector:
    def test_no_alert_during_baseline(self) -> None:
        det = NewIPDetector(NewIPThreshold(enabled=True), baseline_period=9999)
        result = det.process(make_packet(src_ip="1.2.3.4"))
        assert result is None

    def test_alert_after_baseline(self) -> None:
        det = NewIPDetector(NewIPThreshold(enabled=True), baseline_period=0)
        # First packet for a new IP after baseline
        result = det.process(make_packet(src_ip="1.2.3.4"))
        assert result is not None
        assert result.alert_type == "NEW_IP"
        assert result.level == ThreatLevel.LOW

    def test_no_duplicate_alert_same_ip(self) -> None:
        det = NewIPDetector(NewIPThreshold(enabled=True), baseline_period=0)
        results = [det.process(make_packet(src_ip="1.2.3.4")) for _ in range(5)]
        non_none = [r for r in results if r is not None]
        assert len(non_none) == 1

    def test_disabled(self) -> None:
        det = NewIPDetector(NewIPThreshold(enabled=False), baseline_period=0)
        result = det.process(make_packet(src_ip="5.5.5.5"))
        assert result is None

    def test_known_ip_no_alert(self) -> None:
        det = NewIPDetector(NewIPThreshold(enabled=True), baseline_period=0)
        # Add both src and dst IPs as known so no alert fires
        det.add_known_ip("9.9.9.9")
        det.add_known_ip("10.0.0.1")  # default dst_ip in make_packet
        result = det.process(make_packet(src_ip="9.9.9.9"))
        assert result is None
