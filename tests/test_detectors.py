"""Tests for threat detectors."""
from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from netwatchm.config import (
    AdultDomainConfig,
    BruteForceThreshold,
    DataHogConfig,
    ExfiltrationThreshold,
    NewIPThreshold,
    PortScanThreshold,
    TorExitConfig,
    TrackerDomainConfig,
)
from netwatchm.detector.adult_domain import AdultDomainDetector
from netwatchm.detector.brute_force import BruteForceDetector
from netwatchm.detector.data_hog import DataHogDetector
from netwatchm.detector.exfiltration import ExfiltrationDetector
from netwatchm.detector.new_ip import NewIPDetector
from netwatchm.detector.port_scan import PortScanDetector
from netwatchm.detector.tor_exit import TorExitDetector
from netwatchm.detector.tracker_domain import TrackerDomainDetector
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
            result = det.process(make_packet(src_ip="1.2.3.4", dst_port=80))
        assert result is None

    def test_no_alert_internal_src(self) -> None:
        det = self._detector(attempts=2)
        results = [det.process(make_packet(src_ip="192.168.1.50", dst_port=22)) for _ in range(5)]
        assert all(r is None for r in results)

    def test_alert_at_threshold(self) -> None:
        det = self._detector(attempts=3)
        alert = None
        for _ in range(4):
            r = det.process(make_packet(src_ip="1.2.3.4", dst_port=22))
            if r:
                alert = r
        assert alert is not None
        assert alert.alert_type == "BRUTE_FORCE"
        assert alert.level == ThreatLevel.HIGH

    def test_no_duplicate_alert(self) -> None:
        det = self._detector(attempts=2)
        alerts = [det.process(make_packet(src_ip="1.2.3.4", dst_port=22)) for _ in range(10)]
        non_none = [a for a in alerts if a is not None]
        assert len(non_none) == 1

    def test_flush_expired(self) -> None:
        det = self._detector(attempts=2, window=1)
        for _ in range(3):
            det.process(make_packet(src_ip="1.2.3.4", dst_port=22))
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


# ──────────────── Tor Exit ────────────────

class TestTorExitDetector:
    TOR_IP = "198.51.100.1"  # fake Tor exit IP for testing

    def _detector(self, **kwargs) -> TorExitDetector:
        cfg = TorExitConfig(**{"alert_window_seconds": 10, **kwargs})
        return TorExitDetector(cfg, exit_ips={self.TOR_IP})

    def test_no_alert_normal_traffic(self) -> None:
        det = self._detector()
        result = det.process(make_packet(src_ip="192.168.1.1", dst_ip="8.8.8.8"))
        assert result is None

    def test_alert_inbound_tor_src(self) -> None:
        det = self._detector()
        result = det.process(make_packet(src_ip=self.TOR_IP, dst_ip="192.168.1.1"))
        assert result is not None
        assert result.alert_type == "TOR_EXIT"
        assert result.level == ThreatLevel.HIGH
        assert "inbound from Tor" in result.description
        assert self.TOR_IP in result.description

    def test_alert_outbound_tor_dst(self) -> None:
        det = self._detector()
        result = det.process(make_packet(src_ip="192.168.1.1", dst_ip=self.TOR_IP))
        assert result is not None
        assert result.alert_type == "TOR_EXIT"
        assert result.level == ThreatLevel.MEDIUM
        assert "outbound to Tor" in result.description
        assert self.TOR_IP in result.description

    def test_dedup_suppresses_second_alert(self) -> None:
        det = self._detector()
        first = det.process(make_packet(src_ip=self.TOR_IP, dst_ip="192.168.1.1"))
        second = det.process(make_packet(src_ip=self.TOR_IP, dst_ip="192.168.1.1"))
        assert first is not None
        assert second is None

    def test_dedup_expires_and_re_alerts(self) -> None:
        det = self._detector(alert_window_seconds=1)
        first = det.process(make_packet(src_ip=self.TOR_IP, dst_ip="192.168.1.1"))
        assert first is not None
        # Manually backdate the recorded alert time to simulate window expiry
        det._alerted[self.TOR_IP] = time.time() - 2
        second = det.process(make_packet(src_ip=self.TOR_IP, dst_ip="192.168.1.1"))
        assert second is not None

    def test_disabled_no_alert(self) -> None:
        det = self._detector(enabled=False)
        result = det.process(make_packet(src_ip=self.TOR_IP, dst_ip="192.168.1.1"))
        assert result is None

    def test_flush_expired_clears_alerted(self) -> None:
        det = self._detector(alert_window_seconds=1)
        det.process(make_packet(src_ip=self.TOR_IP, dst_ip="192.168.1.1"))
        assert self.TOR_IP in det._alerted
        # Backdate to make entry expired
        det._alerted[self.TOR_IP] = time.time() - 2
        det.flush_expired()
        assert self.TOR_IP not in det._alerted

    def test_alert_type_and_level(self) -> None:
        det = self._detector()
        result = det.process(make_packet(src_ip=self.TOR_IP, dst_ip="10.0.0.1"))
        assert result is not None
        assert result.alert_type == "TOR_EXIT"
        assert result.level == ThreatLevel.HIGH


# ──────────────── Adult Domain ────────────────

class TestAdultDomainDetector:
    ADULT_DOMAIN = "xvideos.com"  # fake domain in test set

    def _detector(self, **kwargs) -> AdultDomainDetector:
        cfg = AdultDomainConfig(**{"alert_window_seconds": 10, **kwargs})
        return AdultDomainDetector(cfg, domain_set={self.ADULT_DOMAIN})

    def test_no_alert_normal_dns(self) -> None:
        det = self._detector()
        result = det.process(make_packet(dns_query="example.com"))
        assert result is None

    def test_alert_on_dns_query(self) -> None:
        det = self._detector()
        result = det.process(make_packet(dns_query=self.ADULT_DOMAIN))
        assert result is not None
        assert result.alert_type == "ADULT_DOMAIN"
        assert result.level == ThreatLevel.MEDIUM
        assert "DNS" in result.description
        assert self.ADULT_DOMAIN in result.description

    def test_alert_on_sni(self) -> None:
        det = self._detector()
        result = det.process(make_packet(sni=self.ADULT_DOMAIN))
        assert result is not None
        assert result.alert_type == "ADULT_DOMAIN"
        assert "SNI" in result.description

    def test_dns_takes_priority_over_sni(self) -> None:
        det = self._detector()
        result = det.process(make_packet(dns_query=self.ADULT_DOMAIN, sni=self.ADULT_DOMAIN))
        assert result is not None
        assert "DNS" in result.description

    def test_dedup_suppresses_second(self) -> None:
        det = self._detector()
        first = det.process(make_packet(dns_query=self.ADULT_DOMAIN))
        second = det.process(make_packet(dns_query=self.ADULT_DOMAIN))
        assert first is not None
        assert second is None

    def test_dedup_per_device(self) -> None:
        det = self._detector()
        r1 = det.process(make_packet(src_ip="192.168.1.1", dns_query=self.ADULT_DOMAIN))
        r2 = det.process(make_packet(src_ip="192.168.1.2", dns_query=self.ADULT_DOMAIN))
        assert r1 is not None
        assert r2 is not None

    def test_dedup_expires_re_alerts(self) -> None:
        det = self._detector(alert_window_seconds=1)
        first = det.process(make_packet(dns_query=self.ADULT_DOMAIN))
        assert first is not None
        key = f"192.168.1.100:{self.ADULT_DOMAIN}"
        det._alerted[key] = time.time() - 2
        second = det.process(make_packet(dns_query=self.ADULT_DOMAIN))
        assert second is not None

    def test_disabled_no_alert(self) -> None:
        det = self._detector(enabled=False)
        result = det.process(make_packet(dns_query=self.ADULT_DOMAIN))
        assert result is None

    def test_flush_expired_clears_alerted(self) -> None:
        det = self._detector(alert_window_seconds=1)
        det.process(make_packet(dns_query=self.ADULT_DOMAIN))
        key = f"192.168.1.100:{self.ADULT_DOMAIN}"
        assert key in det._alerted
        det._alerted[key] = time.time() - 2
        det.flush_expired()
        assert key not in det._alerted

    def test_alert_type_and_level(self) -> None:
        det = self._detector()
        result = det.process(make_packet(dns_query=self.ADULT_DOMAIN))
        assert result is not None
        assert result.alert_type == "ADULT_DOMAIN"
        assert result.level == ThreatLevel.MEDIUM

    def test_extra_domains_blocked(self) -> None:
        det = AdultDomainDetector(
            AdultDomainConfig(alert_window_seconds=10, extra_domains=["custom-adult.example"]),
            domain_set=set(),
        )
        result = det.process(make_packet(dns_query="custom-adult.example"))
        assert result is not None
        assert result.alert_type == "ADULT_DOMAIN"

    def test_fqdn_trailing_dot_stripped(self) -> None:
        det = self._detector()
        result = det.process(make_packet(dns_query=f"{self.ADULT_DOMAIN}."))
        assert result is not None
        assert self.ADULT_DOMAIN in result.description


# ──────────────── Tracker Domain ────────────────

class TestTrackerDomainDetector:
    TRACKER = "api.segment.io"

    def _detector(self, **kwargs) -> TrackerDomainDetector:
        cfg = TrackerDomainConfig(**{"alert_window_seconds": 10, **kwargs})
        return TrackerDomainDetector(cfg, domain_set={self.TRACKER})

    def test_no_alert_normal_dns(self) -> None:
        det = self._detector()
        assert det.process(make_packet(dns_query="google.com")) is None

    def test_alert_on_dns_query(self) -> None:
        det = self._detector()
        result = det.process(make_packet(dns_query=self.TRACKER))
        assert result is not None
        assert result.alert_type == "TRACKER_DOMAIN"
        assert result.level == ThreatLevel.LOW
        assert "DNS" in result.description
        assert self.TRACKER in result.description

    def test_alert_on_sni(self) -> None:
        det = self._detector()
        result = det.process(make_packet(sni=self.TRACKER))
        assert result is not None
        assert result.alert_type == "TRACKER_DOMAIN"
        assert "SNI" in result.description

    def test_dedup_suppresses_second(self) -> None:
        det = self._detector()
        first = det.process(make_packet(dns_query=self.TRACKER))
        second = det.process(make_packet(dns_query=self.TRACKER))
        assert first is not None
        assert second is None

    def test_dedup_per_device(self) -> None:
        det = self._detector()
        r1 = det.process(make_packet(src_ip="192.168.1.1", dns_query=self.TRACKER))
        r2 = det.process(make_packet(src_ip="192.168.1.2", dns_query=self.TRACKER))
        assert r1 is not None
        assert r2 is not None

    def test_dedup_expires_re_alerts(self) -> None:
        det = self._detector(alert_window_seconds=1)
        first = det.process(make_packet(dns_query=self.TRACKER))
        assert first is not None
        key = f"192.168.1.100:{self.TRACKER}"
        det._alerted[key] = time.time() - 2
        second = det.process(make_packet(dns_query=self.TRACKER))
        assert second is not None

    def test_disabled_no_alert(self) -> None:
        det = self._detector(enabled=False)
        assert det.process(make_packet(dns_query=self.TRACKER)) is None

    def test_extra_domains_blocked(self) -> None:
        det = TrackerDomainDetector(
            TrackerDomainConfig(alert_window_seconds=10, extra_domains=["custom-tracker.example"]),
            domain_set=set(),
        )
        result = det.process(make_packet(dns_query="custom-tracker.example"))
        assert result is not None
        assert result.alert_type == "TRACKER_DOMAIN"

    def test_fqdn_trailing_dot_stripped(self) -> None:
        det = self._detector()
        result = det.process(make_packet(dns_query=f"{self.TRACKER}."))
        assert result is not None
        assert self.TRACKER in result.description

    def test_flush_expired_clears_alerted(self) -> None:
        det = self._detector(alert_window_seconds=1)
        det.process(make_packet(dns_query=self.TRACKER))
        key = f"192.168.1.100:{self.TRACKER}"
        assert key in det._alerted
        det._alerted[key] = time.time() - 2
        det.flush_expired()
        assert key not in det._alerted


# ──────────────── Data Hog ────────────────

class TestDataHogDetector:
    LOCAL = "192.168.1.50"
    EXTERNAL = "8.8.8.8"

    def _detector(self, threshold=1000, window=86400, alert_window=10) -> DataHogDetector:
        cfg = DataHogConfig(
            bytes_per_24h=threshold,
            window_seconds=window,
            alert_window_seconds=alert_window,
        )
        return DataHogDetector(cfg)

    def test_no_alert_below_threshold(self) -> None:
        det = self._detector(threshold=10_000)
        for _ in range(5):
            result = det.process(make_packet(src_ip=self.LOCAL, dst_ip=self.EXTERNAL, length=100))
        assert result is None

    def test_alert_on_sent_bytes(self) -> None:
        det = self._detector(threshold=500)
        alert = None
        for _ in range(6):
            r = det.process(make_packet(src_ip=self.LOCAL, dst_ip=self.EXTERNAL, length=100))
            if r:
                alert = r
        assert alert is not None
        assert alert.alert_type == "DATA_HOG"
        assert alert.level == ThreatLevel.HIGH
        assert self.LOCAL in alert.description

    def test_alert_on_received_bytes(self) -> None:
        # External → local (download): should count toward local device
        det = self._detector(threshold=500)
        alert = None
        for _ in range(6):
            r = det.process(make_packet(src_ip=self.EXTERNAL, dst_ip=self.LOCAL, length=100))
            if r:
                alert = r
        assert alert is not None
        assert alert.alert_type == "DATA_HOG"
        assert self.LOCAL in alert.description

    def test_no_alert_external_src(self) -> None:
        # External → external should never alert
        det = self._detector(threshold=100)
        for _ in range(10):
            result = det.process(make_packet(src_ip=self.EXTERNAL, dst_ip="1.1.1.1", length=100))
        assert result is None

    def test_local_to_local_no_double_count(self) -> None:
        # Local → local: only src_ip counted (no double-count)
        LOCAL2 = "192.168.1.51"
        det = self._detector(threshold=500)
        alerts = []
        for _ in range(6):
            r = det.process(make_packet(src_ip=self.LOCAL, dst_ip=LOCAL2, length=100))
            if r:
                alerts.append(r)
        # src_ip should still alert (600 bytes sent)
        assert len(alerts) == 1
        assert alerts[0].src_ip == self.LOCAL

    def test_different_devices_independent(self) -> None:
        LOCAL2 = "192.168.1.51"
        det = self._detector(threshold=500)
        alert1, alert2 = None, None
        for _ in range(6):
            r = det.process(make_packet(src_ip=self.LOCAL, dst_ip=self.EXTERNAL, length=100))
            if r:
                alert1 = r
        for _ in range(6):
            r = det.process(make_packet(src_ip=LOCAL2, dst_ip=self.EXTERNAL, length=100))
            if r:
                alert2 = r
        assert alert1 is not None
        assert alert2 is not None
        assert alert1.src_ip != alert2.src_ip

    def test_dedup_suppresses_second_alert(self) -> None:
        det = self._detector(threshold=500)
        alerts = []
        for _ in range(20):
            r = det.process(make_packet(src_ip=self.LOCAL, dst_ip=self.EXTERNAL, length=100))
            if r:
                alerts.append(r)
        assert len(alerts) == 1

    def test_dedup_expires_re_alerts(self) -> None:
        det = self._detector(threshold=500, alert_window=1)
        first = None
        for _ in range(6):
            r = det.process(make_packet(src_ip=self.LOCAL, dst_ip=self.EXTERNAL, length=100))
            if r:
                first = r
        assert first is not None
        det._alerted[self.LOCAL] = time.time() - 2
        second = det.process(make_packet(src_ip=self.LOCAL, dst_ip=self.EXTERNAL, length=100))
        assert second is not None

    def test_disabled_no_alert(self) -> None:
        cfg = DataHogConfig(enabled=False, bytes_per_24h=100)
        det = DataHogDetector(cfg)
        for _ in range(10):
            result = det.process(make_packet(src_ip=self.LOCAL, dst_ip=self.EXTERNAL, length=100))
        assert result is None

    def test_flush_expired_removes_old_data(self) -> None:
        det = self._detector(threshold=500, window=1)
        for _ in range(3):
            det.process(make_packet(src_ip=self.LOCAL, dst_ip=self.EXTERNAL, length=100))
        assert self.LOCAL in det._windows
        det._windows[self.LOCAL][0] = (time.time() - 2, 100)
        # backdate all entries
        old_dq = det._windows[self.LOCAL]
        det._windows[self.LOCAL] = type(old_dq)((time.time() - 2, b) for _, b in old_dq)
        det.flush_expired()
        assert self.LOCAL not in det._windows

    def test_alert_type_and_level(self) -> None:
        det = self._detector(threshold=500)
        alert = None
        for _ in range(6):
            r = det.process(make_packet(src_ip=self.LOCAL, dst_ip=self.EXTERNAL, length=100))
            if r:
                alert = r
        assert alert is not None
        assert alert.alert_type == "DATA_HOG"
        assert alert.level == ThreatLevel.HIGH

    def test_description_shows_volume_and_threshold(self) -> None:
        det = self._detector(threshold=500)
        alert = None
        for _ in range(6):
            r = det.process(make_packet(src_ip=self.LOCAL, dst_ip=self.EXTERNAL, length=100))
            if r:
                alert = r
        assert alert is not None
        assert "threshold" in alert.description
        assert self.LOCAL in alert.description
