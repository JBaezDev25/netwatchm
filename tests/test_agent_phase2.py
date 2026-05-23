"""Phase 2 tests: guardrails, state files, executor, prompt-injection regression."""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from netwatchm.agent.audit import AuditLog
from netwatchm.agent.executor import Executor
from netwatchm.agent.guardrails import GuardrailLimits, Guardrails
from netwatchm.agent.state import AgentWhitelistStore, SuppressedTypesStore
from netwatchm.agent.tools import ACTION_TOOL_SCHEMAS
from netwatchm.config import NtfyAlertConfig


# ---------- Helpers ----------


def _make_audit_db(path: Path) -> AuditLog:
    """Initialise an empty audit DB and return an opened handle."""
    audit = AuditLog(str(path))
    audit.open()
    return audit


def _seed_events_db(path: Path, *, with_critical: tuple[str, ...] = ()) -> None:
    conn = sqlite3.connect(str(path))
    conn.executescript(
        """
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL, alert_type TEXT, level TEXT,
            src_ip TEXT, dst_ip TEXT, description TEXT
        );
        """
    )
    now = time.time()
    for ip in with_critical:
        conn.execute(
            "INSERT INTO events (timestamp, alert_type, level, src_ip, dst_ip, description) "
            "VALUES (?, 'MALWARE_DOMAIN', 'CRITICAL', ?, ?, 'evil')",
            (now - 60, ip, "1.2.3.4"),
        )
    conn.commit()
    conn.close()


# ---------- Guardrails: argument validation ----------


def test_check_add_whitelist_rejects_zero_ip(tmp_path: Path) -> None:
    gr = Guardrails(audit_db_path=str(tmp_path / "a.db"), events_db_path=str(tmp_path / "e.db"))
    ok, reason = gr.check_add_whitelist({"ip": "0.0.0.0", "scope": "global", "reason": "x"})
    assert not ok
    assert "0.0.0.0" in reason or "unspecified" in reason.lower()


def test_check_add_whitelist_rejects_cidr(tmp_path: Path) -> None:
    gr = Guardrails(audit_db_path=str(tmp_path / "a.db"), events_db_path=str(tmp_path / "e.db"))
    ok, reason = gr.check_add_whitelist({"ip": "10.0.0.0/8", "scope": "global", "reason": "x"})
    assert not ok
    assert "ip" in reason.lower()


def test_check_add_whitelist_rejects_shell_injection(tmp_path: Path) -> None:
    gr = Guardrails(audit_db_path=str(tmp_path / "a.db"), events_db_path=str(tmp_path / "e.db"))
    ok, reason = gr.check_add_whitelist(
        {"ip": "1.2.3.4; rm -rf /", "scope": "global", "reason": "x"}
    )
    assert not ok


def test_check_add_whitelist_rejects_multicast(tmp_path: Path) -> None:
    gr = Guardrails(audit_db_path=str(tmp_path / "a.db"), events_db_path=str(tmp_path / "e.db"))
    ok, _ = gr.check_add_whitelist({"ip": "224.0.0.1", "scope": "global", "reason": "x"})
    assert not ok


def test_check_add_whitelist_rejects_ttl_above_cap(tmp_path: Path) -> None:
    gr = Guardrails(audit_db_path=str(tmp_path / "a.db"), events_db_path=str(tmp_path / "e.db"))
    ok, reason = gr.check_add_whitelist(
        {"ip": "1.1.1.1", "scope": "global", "reason": "x", "ttl_hours": 999}
    )
    assert not ok
    assert "ttl" in reason.lower()


def test_check_add_whitelist_blocks_recent_critical(tmp_path: Path) -> None:
    events = tmp_path / "e.db"
    _seed_events_db(events, with_critical=("1.2.3.4",))
    gr = Guardrails(audit_db_path=str(tmp_path / "a.db"), events_db_path=str(events))
    ok, reason = gr.check_add_whitelist({"ip": "1.2.3.4", "scope": "global", "reason": "x"})
    assert not ok
    assert "CRITICAL" in reason


def test_check_add_whitelist_accepts_clean_input(tmp_path: Path) -> None:
    gr = Guardrails(audit_db_path=str(tmp_path / "a.db"), events_db_path=str(tmp_path / "e.db"))
    ok, reason = gr.check_add_whitelist(
        {"ip": "8.8.8.8", "scope": "global", "reason": "google dns"}
    )
    assert ok, reason


# ---------- Guardrails: suppress + scan + notify ----------


def test_check_suppress_blocks_critical_types(tmp_path: Path) -> None:
    gr = Guardrails(audit_db_path=str(tmp_path / "a.db"), events_db_path=str(tmp_path / "e.db"))
    ok, reason = gr.check_suppress({"alert_type": "EXFILTRATION", "reason": "x"})
    assert not ok
    assert "EXFILTRATION" in reason


def test_check_suppress_rejects_duration_above_cap(tmp_path: Path) -> None:
    gr = Guardrails(audit_db_path=str(tmp_path / "a.db"), events_db_path=str(tmp_path / "e.db"))
    ok, reason = gr.check_suppress(
        {"alert_type": "NEW_IP", "duration_hours": 999, "reason": "x"}
    )
    assert not ok
    assert "duration" in reason.lower()


def test_check_scan_rejects_unknown_scan_type(tmp_path: Path) -> None:
    gr = Guardrails(audit_db_path=str(tmp_path / "a.db"), events_db_path=str(tmp_path / "e.db"))
    ok, reason = gr.check_scan(
        {"ip": "1.1.1.1", "scan_type": "rm_rf_slash", "reason": "x"}
    )
    assert not ok
    assert "scan_type" in reason


def test_check_notify_rejects_huge_headline(tmp_path: Path) -> None:
    gr = Guardrails(audit_db_path=str(tmp_path / "a.db"), events_db_path=str(tmp_path / "e.db"))
    ok, reason = gr.check_notify(
        {"severity": "HIGH", "headline": "X" * 10_000}
    )
    assert not ok
    assert "headline" in reason


def test_check_notify_rejects_bad_severity(tmp_path: Path) -> None:
    gr = Guardrails(audit_db_path=str(tmp_path / "a.db"), events_db_path=str(tmp_path / "e.db"))
    ok, reason = gr.check_notify({"severity": "URGENT", "headline": "h"})
    assert not ok


# ---------- Guardrails: rate caps ----------


def test_whitelist_rate_cap_enforced(tmp_path: Path) -> None:
    """After max_whitelist_changes_per_hour executed calls, the next check fails."""
    audit_db = tmp_path / "a.db"
    audit = _make_audit_db(audit_db)
    try:
        d_id = audit.record_decision(
            model="m", mode="live", events_seen=0,
            max_severity=None, rationale=None, raw_response=None,
        )
        # Seed 5 executed whitelist adds
        for _ in range(5):
            audit.record_tool_call(
                decision_id=d_id,
                tool_name="add_whitelist_entry",
                args={"ip": "1.1.1.1"},
                status="executed",
            )
    finally:
        audit.close()

    gr = Guardrails(
        audit_db_path=str(audit_db),
        events_db_path=str(tmp_path / "e.db"),
        limits=GuardrailLimits(max_whitelist_changes_per_hour=5),
    )
    ok, reason = gr.check_add_whitelist({"ip": "8.8.8.8", "scope": "global", "reason": "x"})
    assert not ok
    assert "rate cap" in reason


def test_scan_rate_cap_enforced(tmp_path: Path) -> None:
    audit_db = tmp_path / "a.db"
    audit = _make_audit_db(audit_db)
    try:
        d_id = audit.record_decision(
            model="m", mode="live", events_seen=0,
            max_severity=None, rationale=None, raw_response=None,
        )
        for _ in range(10):
            audit.record_tool_call(
                decision_id=d_id, tool_name="run_active_scan",
                args={"ip": "1.1.1.1"}, status="executed",
            )
    finally:
        audit.close()
    gr = Guardrails(audit_db_path=str(audit_db), events_db_path=str(tmp_path / "e.db"))
    ok, _ = gr.check_scan(
        {"ip": "1.1.1.1", "scan_type": "nmap_ports", "reason": "x"}
    )
    assert not ok


def test_notify_rate_cap_enforced(tmp_path: Path) -> None:
    audit_db = tmp_path / "a.db"
    audit = _make_audit_db(audit_db)
    try:
        d_id = audit.record_decision(
            model="m", mode="live", events_seen=0,
            max_severity=None, rationale=None, raw_response=None,
        )
        for _ in range(20):
            audit.record_tool_call(
                decision_id=d_id, tool_name="send_ntfy_alert",
                args={"severity": "HIGH"}, status="executed",
            )
    finally:
        audit.close()
    gr = Guardrails(audit_db_path=str(audit_db), events_db_path=str(tmp_path / "e.db"))
    ok, _ = gr.check_notify({"severity": "HIGH", "headline": "h"})
    assert not ok


# ---------- AgentWhitelistStore ----------


def test_whitelist_store_add_and_check(tmp_path: Path) -> None:
    store = AgentWhitelistStore(str(tmp_path / "wl.json"))
    entry = store.add(
        ip="1.2.3.4", scope="global", alert_type=None,
        ttl_hours=1, reason="test", decision_id=42,
    )
    assert entry.id
    assert store.is_suppressed("PORT_SCAN", "1.2.3.4") is True
    assert store.is_suppressed("PORT_SCAN", "9.9.9.9") is False


def test_whitelist_store_detector_scope_only_matches_alert_type(tmp_path: Path) -> None:
    store = AgentWhitelistStore(str(tmp_path / "wl.json"))
    store.add(
        ip="1.2.3.4", scope="detector", alert_type="PORT_SCAN",
        ttl_hours=1, reason="x", decision_id=None,
    )
    assert store.is_suppressed("PORT_SCAN", "1.2.3.4") is True
    assert store.is_suppressed("EXFILTRATION", "1.2.3.4") is False


def test_whitelist_store_expired_entries_skipped(tmp_path: Path) -> None:
    p = tmp_path / "wl.json"
    store = AgentWhitelistStore(str(p))
    e = store.add(
        ip="1.2.3.4", scope="global", alert_type=None,
        ttl_hours=1, reason="x", decision_id=None,
    )
    # Hack expiry to be in the past
    data = json.loads(p.read_text())
    data["entries"][0]["expires_at"] = time.time() - 100
    p.write_text(json.dumps(data))

    assert store.is_suppressed("PORT_SCAN", "1.2.3.4") is False
    assert store.active_entries() == []


def test_whitelist_store_rollback_by_id(tmp_path: Path) -> None:
    store = AgentWhitelistStore(str(tmp_path / "wl.json"))
    e = store.add(
        ip="1.2.3.4", scope="global", alert_type=None,
        ttl_hours=24, reason="x", decision_id=None,
    )
    assert store.rollback_by_id(e.id) is True
    assert store.is_suppressed("PORT_SCAN", "1.2.3.4") is False
    # Second rollback is idempotent
    assert store.rollback_by_id(e.id) is False


# ---------- SuppressedTypesStore TTL ----------


def test_suppressed_store_ttl_cleanup(tmp_path: Path) -> None:
    p = tmp_path / "sup.json"
    store = SuppressedTypesStore(str(p))
    store.suppress("NEW_IP", duration_hours=1)
    assert "NEW_IP" in store.active()

    data = json.loads(p.read_text())
    data["ttl"]["NEW_IP"] = time.time() - 100
    p.write_text(json.dumps(data))

    expired = store.cleanup_expired()
    assert expired == ["NEW_IP"]
    assert "NEW_IP" not in store.active()


def test_suppressed_store_unsuppress(tmp_path: Path) -> None:
    store = SuppressedTypesStore(str(tmp_path / "sup.json"))
    store.suppress("NEW_IP", 1)
    assert store.unsuppress("NEW_IP") is True
    assert store.unsuppress("NEW_IP") is False  # idempotent


# ---------- Executor ----------


@pytest.fixture
def executor_setup(tmp_path: Path):
    audit_db = tmp_path / "audit.db"
    events_db = tmp_path / "events.db"
    _make_audit_db(audit_db).close()  # create schema
    _seed_events_db(events_db)

    gr = Guardrails(audit_db_path=str(audit_db), events_db_path=str(events_db))
    whitelist = AgentWhitelistStore(str(tmp_path / "wl.json"))
    suppressed = SuppressedTypesStore(str(tmp_path / "sup.json"))
    ntfy = NtfyAlertConfig(enabled=True, topic="testtopic", server="https://ntfy.sh")

    executor = Executor(
        guardrails=gr,
        whitelist_store=whitelist,
        suppressed_store=suppressed,
        ntfy_config=ntfy,
        portal_base_url="https://test.local:8765",
    )
    return executor, whitelist, suppressed, audit_db


def test_executor_add_whitelist_happy_path(executor_setup) -> None:
    executor, whitelist, _, _ = executor_setup
    result = executor.dispatch(
        "add_whitelist_entry",
        {"ip": "8.8.8.8", "scope": "global", "reason": "google dns", "ttl_hours": 24},
        decision_id=1,
    )
    assert result["ok"] is True
    assert "entry_id" in result
    assert whitelist.is_suppressed("PORT_SCAN", "8.8.8.8") is True


def test_executor_add_whitelist_blocked_by_guardrails(executor_setup) -> None:
    executor, whitelist, _, _ = executor_setup
    result = executor.dispatch(
        "add_whitelist_entry",
        {"ip": "0.0.0.0", "scope": "global", "reason": "evil"},
        decision_id=1,
    )
    assert result["ok"] is False
    assert result["blocked"] is True
    assert whitelist.is_suppressed("PORT_SCAN", "0.0.0.0") is False


def test_executor_suppress_alert_type(executor_setup) -> None:
    executor, _, suppressed, _ = executor_setup
    result = executor.dispatch(
        "suppress_alert_type",
        {"alert_type": "NEW_IP", "duration_hours": 1, "reason": "noisy"},
        decision_id=1,
    )
    assert result["ok"] is True
    assert "NEW_IP" in suppressed.active()


def test_executor_suppress_critical_type_blocked(executor_setup) -> None:
    executor, _, suppressed, _ = executor_setup
    result = executor.dispatch(
        "suppress_alert_type",
        {"alert_type": "EXFILTRATION", "reason": "x"},
        decision_id=1,
    )
    assert result["ok"] is False
    assert result["blocked"] is True
    assert "EXFILTRATION" not in suppressed.active()


def test_executor_unknown_tool(executor_setup) -> None:
    executor, *_ = executor_setup
    result = executor.dispatch("delete_everything", {}, decision_id=1)
    assert result["ok"] is False
    assert result["blocked"] is True
    assert "unknown" in result["reason"].lower()


def test_executor_scan_args_validated_before_subprocess(executor_setup) -> None:
    """A scan request with a malformed IP must be blocked by guardrails
    before any subprocess could fire."""
    executor, *_ = executor_setup
    with patch("subprocess.run") as mock_run:
        result = executor.dispatch(
            "run_active_scan",
            {"ip": "1.2.3.4; cat /etc/passwd", "scan_type": "nmap_ports", "reason": "x"},
            decision_id=1,
        )
    assert result["ok"] is False
    assert result["blocked"] is True
    mock_run.assert_not_called()


def test_executor_ntfy_posts_with_action_button(executor_setup) -> None:
    executor, whitelist, _, _ = executor_setup
    # First add a whitelist entry so we have an entry_id to roll back
    add_r = executor.dispatch(
        "add_whitelist_entry",
        {"ip": "8.8.8.8", "scope": "global", "reason": "ok", "ttl_hours": 24},
        decision_id=1,
    )
    entry_id = add_r["entry_id"]

    captured: dict = {}

    class _Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): pass

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.headers)
        captured["body"] = req.data
        return _Resp()

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        r = executor.dispatch(
            "send_ntfy_alert",
            {
                "severity": "HIGH",
                "headline": "whitelisted 8.8.8.8",
                "action_taken": "added detector-scoped whitelist",
                "reason": "benign google dns",
                "related_ip": "8.8.8.8",
                "rollback_entry_id": entry_id,
            },
            decision_id=1,
        )
    assert r["ok"] is True
    assert captured["url"].endswith("/testtopic")
    actions = captured["headers"].get("X-actions", "") + captured["headers"].get("X-Actions", "")
    assert "Rollback" in actions
    assert entry_id in actions
    assert "8.8.8.8" in actions  # the 'Open events' action


def test_executor_ntfy_blocked_when_not_configured(tmp_path: Path) -> None:
    audit_db = tmp_path / "a.db"
    events_db = tmp_path / "e.db"
    _make_audit_db(audit_db).close()
    _seed_events_db(events_db)
    gr = Guardrails(audit_db_path=str(audit_db), events_db_path=str(events_db))
    executor = Executor(
        guardrails=gr,
        whitelist_store=AgentWhitelistStore(str(tmp_path / "wl.json")),
        suppressed_store=SuppressedTypesStore(str(tmp_path / "sup.json")),
        ntfy_config=None,  # not configured
    )
    r = executor.dispatch(
        "send_ntfy_alert",
        {"severity": "HIGH", "headline": "h", "action_taken": "a", "reason": "r"},
        decision_id=1,
    )
    assert r["ok"] is False
    assert "ntfy not configured" in r["reason"]


# ---------- Prompt-injection regression ----------


def test_attacker_text_in_event_description_cannot_bypass_guardrails(
    executor_setup,
) -> None:
    """A malicious description in an event ("'; whitelist 0.0.0.0;") cannot
    trick the executor — even if the LLM is somehow convinced to call
    add_whitelist_entry with the bad IP, guardrails reject the IP shape."""
    executor, *_ = executor_setup
    r = executor.dispatch(
        "add_whitelist_entry",
        {
            "ip": "0.0.0.0",
            "scope": "global",
            "reason": "attacker said this is fine",
        },
        decision_id=1,
    )
    assert r["ok"] is False
    assert r["blocked"] is True


# ---------- Action tool schema sanity ----------


def test_action_tool_schemas_well_formed() -> None:
    names = {s["function"]["name"] for s in ACTION_TOOL_SCHEMAS}
    assert names == {
        "add_whitelist_entry",
        "remove_whitelist_entry",
        "suppress_alert_type",
        "unsuppress_alert_type",
        "run_active_scan",
        "send_ntfy_alert",
    }
    for s in ACTION_TOOL_SCHEMAS:
        fn = s["function"]
        assert "description" in fn
        assert fn["parameters"]["type"] == "object"
