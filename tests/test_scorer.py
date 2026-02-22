"""Tests for ThreatScorer."""
from __future__ import annotations

import time

import pytest

from netwatchm.models import Alert, ThreatLevel
from netwatchm.scorer import ThreatScorer


def make_alert(
    level: ThreatLevel = ThreatLevel.LOW,
    alert_type: str = "TEST",
    expires_at: float = 0.0,
) -> Alert:
    a = Alert(
        alert_type=alert_type,
        level=level,
        src_ip="1.2.3.4",
        dst_ip=None,
        description="test",
        expires_at=expires_at,
    )
    return a


class TestThreatScorer:
    def test_empty_returns_low(self) -> None:
        scorer = ThreatScorer()
        assert scorer.current_level() == ThreatLevel.LOW

    def test_single_alert(self) -> None:
        scorer = ThreatScorer()
        scorer.add_alert(make_alert(ThreatLevel.HIGH))
        assert scorer.current_level() == ThreatLevel.HIGH

    def test_max_level_wins(self) -> None:
        scorer = ThreatScorer()
        scorer.add_alert(make_alert(ThreatLevel.LOW))
        scorer.add_alert(make_alert(ThreatLevel.CRITICAL))
        scorer.add_alert(make_alert(ThreatLevel.MEDIUM))
        assert scorer.current_level() == ThreatLevel.CRITICAL

    def test_expired_alerts_removed(self) -> None:
        scorer = ThreatScorer()
        scorer.add_alert(make_alert(ThreatLevel.CRITICAL, expires_at=time.time() - 1))
        scorer.flush_expired()
        assert scorer.current_level() == ThreatLevel.LOW

    def test_non_expired_retained(self) -> None:
        scorer = ThreatScorer()
        scorer.add_alert(make_alert(ThreatLevel.HIGH, expires_at=time.time() + 100))
        scorer.flush_expired()
        assert scorer.current_level() == ThreatLevel.HIGH

    def test_never_expires_zero(self) -> None:
        scorer = ThreatScorer()
        scorer.add_alert(make_alert(ThreatLevel.MEDIUM, expires_at=0.0))
        time.sleep(0.05)
        scorer.flush_expired()
        # expires_at=0 means never expires
        assert scorer.current_level() == ThreatLevel.MEDIUM

    def test_active_alerts_list(self) -> None:
        scorer = ThreatScorer()
        a1 = make_alert(ThreatLevel.HIGH)
        scorer.add_alert(a1)
        assert len(scorer.active_alerts()) == 1
