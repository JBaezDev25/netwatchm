"""Tests for the periodic threat digest (agent mode: digest) + ntfy exclusion."""
from __future__ import annotations

import asyncio
import time
from datetime import datetime
from unittest.mock import MagicMock, patch

from netwatchm.agent import agent_loop
from netwatchm.agent.audit import AuditLog
from netwatchm.agent.digest import build_digest, push_digest, render_fallback
from netwatchm.agent.llm_client import LlmResponse
from netwatchm.alerts.event_store import EventStore
from netwatchm.alerts.ntfy_alert import NtfyAlert
from netwatchm.config import AgentConfig, NtfyAlertConfig
from netwatchm.models import Alert, ThreatLevel


def _alert(alert_type, level=ThreatLevel.HIGH, src_ip="10.0.0.5", ts=None):
    a = Alert(
        alert_type=alert_type, level=level, src_ip=src_ip,
        dst_ip="10.0.0.1", description="x",
    )
    if ts is not None:
        object.__setattr__(a, "timestamp", datetime.fromtimestamp(ts))
    return a


def _seed(db_path):
    with EventStore(db_path) as s:
        for _ in range(3):
            s.insert(_alert("PORT_SCAN", ThreatLevel.HIGH, "203.0.113.7"))
        s.insert(_alert("PORT_SCAN", ThreatLevel.HIGH, "203.0.113.9"))
        s.insert(_alert("EXFILTRATION", ThreatLevel.CRITICAL, "10.0.0.50"))
        for _ in range(10):
            s.insert(_alert("BEACONING", ThreatLevel.MEDIUM, "10.0.0.22"))


# --- build_digest ---

class TestBuildDigest:
    def test_counts_and_top_source(self, tmp_path):
        db = str(tmp_path / "events.db")
        _seed(db)
        d = build_digest(events_db_path=db, lookback_days=5)
        by_type = {c["alert_type"]: c for c in d["categories"]}
        assert by_type["PORT_SCAN"]["count"] == 4
        assert by_type["PORT_SCAN"]["distinct_sources"] == 2
        assert by_type["PORT_SCAN"]["top_sources"][0]["ip"] == "203.0.113.7"
        assert by_type["PORT_SCAN"]["top_sources"][0]["hits"] == 3

    def test_beacon_excluded_by_default(self, tmp_path):
        db = str(tmp_path / "events.db")
        _seed(db)
        d = build_digest(events_db_path=db, lookback_days=5)
        types = {c["alert_type"] for c in d["categories"]}
        assert "BEACONING" not in types
        assert d["window"]["excluded_events"] == 10
        assert d["window"]["total_events"] == 5  # 4 port scan + 1 exfil

    def test_worst_severity_first(self, tmp_path):
        db = str(tmp_path / "events.db")
        _seed(db)
        d = build_digest(events_db_path=db, lookback_days=5)
        assert d["categories"][0]["alert_type"] == "EXFILTRATION"
        assert d["categories"][0]["max_level"] == "CRITICAL"

    def test_lookback_window_excludes_old(self, tmp_path):
        db = str(tmp_path / "events.db")
        with EventStore(db) as s:
            s.insert(_alert("PORT_SCAN", ts=time.time()))
            s.insert(_alert("OLD_TYPE", ts=time.time() - 10 * 86400))
        d = build_digest(events_db_path=db, lookback_days=5)
        types = {c["alert_type"] for c in d["categories"]}
        assert "OLD_TYPE" not in types

    def test_missing_db_is_empty(self, tmp_path):
        d = build_digest(events_db_path=str(tmp_path / "nope.db"), lookback_days=5)
        assert d["categories"] == []
        assert d["window"]["total_events"] == 0

    def test_custom_exclude_types(self, tmp_path):
        db = str(tmp_path / "events.db")
        _seed(db)
        d = build_digest(events_db_path=db, lookback_days=5, exclude_types=["PORT_SCAN"])
        types = {c["alert_type"] for c in d["categories"]}
        assert "PORT_SCAN" not in types
        assert "BEACONING" in types  # not excluded now


def test_render_fallback_lists_categories(tmp_path):
    db = str(tmp_path / "events.db")
    _seed(db)
    text = render_fallback(build_digest(events_db_path=db, lookback_days=5))
    assert "EXFILTRATION" in text and "PORT_SCAN" in text
    assert "BEACONING" not in text


def test_render_fallback_quiet_period(tmp_path):
    text = render_fallback(build_digest(events_db_path=str(tmp_path / "x.db"), lookback_days=5))
    assert "Quiet period" in text


# --- push_digest ---

def test_push_digest_posts(monkeypatch):
    calls = {}

    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=10):
        calls["url"] = req.full_url
        calls["body"] = req.data
        return FakeResp()

    monkeypatch.setattr("netwatchm.agent.digest.urllib.request.urlopen", fake_urlopen)
    cfg = NtfyAlertConfig(enabled=True, topic="abc", server="https://ntfy.sh")
    assert push_digest(cfg, "title", "body text") is True
    assert calls["url"] == "https://ntfy.sh/abc"
    assert b"body text" in calls["body"]


def test_push_digest_no_topic_returns_false():
    assert push_digest(NtfyAlertConfig(enabled=True, topic=""), "t", "b") is False


# --- ntfy real-time exclusion ---

def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_ntfy_excludes_beaconing():
    cfg = NtfyAlertConfig(
        enabled=True, topic="t", min_level="LOW", cooldown_seconds=0,
        exclude_types=["BEACONING"],
    )
    handler = NtfyAlert(cfg)
    with patch.object(handler, "_send_sync") as mock_send:
        _run(handler.send(_alert("BEACONING", ThreatLevel.CRITICAL)))
        assert mock_send.call_count == 0
        _run(handler.send(_alert("PORT_SCAN", ThreatLevel.HIGH)))
        assert mock_send.call_count == 1


def test_ntfy_critical_only_min_level():
    cfg = NtfyAlertConfig(
        enabled=True, topic="t", min_level="CRITICAL", cooldown_seconds=0,
        exclude_types=["BEACONING"],
    )
    handler = NtfyAlert(cfg)
    with patch.object(handler, "_send_sync") as mock_send:
        _run(handler.send(_alert("PORT_SCAN", ThreatLevel.HIGH)))
        assert mock_send.call_count == 0  # HIGH < CRITICAL
        _run(handler.send(_alert("EXFILTRATION", ThreatLevel.CRITICAL)))
        assert mock_send.call_count == 1


# --- digest tick end-to-end ---

class _FakeClient:
    model = "mistral:latest"

    def __init__(self, content=None, raises=False):
        self._content = content
        self._raises = raises
        self.called = False

    def chat(self, **kwargs):
        self.called = True
        if self._raises:
            raise RuntimeError("llm down")
        return LlmResponse(content=self._content or "")


def _agent_cfg(**kw):
    return AgentConfig(enabled=True, mode="digest", model="mistral:latest", **kw)


def test_digest_tick_pushes_llm_text(tmp_path):
    db = str(tmp_path / "events.db")
    _seed(db)
    audit = AuditLog(str(tmp_path / "audit.db")).open()
    client = _FakeClient(content="All quiet except port scans.")
    cfg = NtfyAlertConfig(enabled=True, topic="t")
    with patch.object(agent_loop, "push_digest", return_value=True) as mock_push:
        _run(agent_loop._run_digest_tick(
            agent_cfg=_agent_cfg(), client=client, audit=audit,
            events_db_path=db, ntfy_cfg=cfg,
        ))
    assert client.called
    body = mock_push.call_args.args[2]
    assert body == "All quiet except port scans."
    # decision recorded with mode=digest
    row = audit._conn.execute(
        "SELECT mode, events_seen, rationale FROM agent_decisions"
    ).fetchone()
    assert row[0] == "digest"
    assert row[1] == 5
    audit.close()


def test_digest_tick_falls_back_on_llm_error(tmp_path):
    db = str(tmp_path / "events.db")
    _seed(db)
    audit = AuditLog(str(tmp_path / "audit.db")).open()
    client = _FakeClient(raises=True)
    with patch.object(agent_loop, "push_digest", return_value=True) as mock_push:
        _run(agent_loop._run_digest_tick(
            agent_cfg=_agent_cfg(), client=client, audit=audit,
            events_db_path=db, ntfy_cfg=NtfyAlertConfig(enabled=True, topic="t"),
        ))
    body = mock_push.call_args.args[2]
    assert "EXFILTRATION" in body  # fallback render used
    audit.close()
