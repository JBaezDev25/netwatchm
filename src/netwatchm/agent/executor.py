"""Action executor — runs the 5 action tools the agent may call when live.

Every action goes through three steps:
  1. ``guardrails.check_<tool>(args)`` — refuse if any hard limit would be
     violated (rate cap, banned target, malformed args).
  2. State mutation — write to the side-car file or spawn the subprocess.
  3. Audit log — the calling agent loop records the result with the
     status from this module's return value.

This module never silently swallows errors. If a state write fails, the
returned dict has ``ok=False`` and the agent loop records ``status=error``.
If guardrails block the action, the returned dict has ``blocked=True``
and the agent loop records ``status=blocked`` with the reason.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ..config import NtfyAlertConfig
from .guardrails import Guardrails
from .state import AgentWhitelistStore, SuppressedTypesStore

logger = logging.getLogger("netwatchm.agent.executor")


def _result(ok: bool, **fields: Any) -> dict:
    out: dict[str, Any] = {"ok": ok}
    out.update(fields)
    return out


class Executor:
    """Dispatcher for the agent's 5 action tools.

    The executor is stateless apart from the file-backed stores it writes
    to — safe to instantiate per-tick or share across ticks."""

    def __init__(
        self,
        *,
        guardrails: Guardrails,
        whitelist_store: AgentWhitelistStore,
        suppressed_store: SuppressedTypesStore,
        ntfy_config: NtfyAlertConfig | None,
        portal_base_url: str = "https://localhost:8765",
    ) -> None:
        self.guardrails = guardrails
        self.whitelist = whitelist_store
        self.suppressed = suppressed_store
        self.ntfy = ntfy_config
        self.portal_base = portal_base_url.rstrip("/")

    # ----- dispatch -----

    def dispatch(self, tool_name: str, args: dict, *, decision_id: int) -> dict:
        """Single entry point. Returns a dict the caller stores in the audit
        log. Keys: ``ok`` (bool), ``blocked`` (bool), ``reason`` (str),
        and tool-specific result fields."""
        impls = {
            "add_whitelist_entry": self._add_whitelist,
            "remove_whitelist_entry": self._remove_whitelist,
            "suppress_alert_type": self._suppress_alert_type,
            "unsuppress_alert_type": self._unsuppress_alert_type,
            "run_active_scan": self._run_active_scan,
            "send_ntfy_alert": self._send_ntfy_alert,
        }
        fn = impls.get(tool_name)
        if fn is None:
            return _result(False, blocked=True, reason=f"unknown action tool: {tool_name}")
        try:
            return fn(args, decision_id=decision_id)
        except Exception as exc:  # noqa: BLE001
            logger.exception("executor failed on %s", tool_name)
            return _result(False, reason=f"executor exception: {exc}")

    # ----- individual actions -----

    def _add_whitelist(self, args: dict, *, decision_id: int) -> dict:
        ok, reason = self.guardrails.check_add_whitelist(args)
        if not ok:
            return _result(False, blocked=True, reason=reason)
        entry = self.whitelist.add(
            ip=str(args["ip"]).strip(),
            scope=str(args.get("scope", "global")).lower(),
            alert_type=(args.get("alert_type") or None),
            ttl_hours=int(
                args.get("ttl_hours", self.guardrails.limits.max_whitelist_ttl_hours)
            ),
            reason=str(args.get("reason") or "")[:500],
            decision_id=decision_id,
        )
        return _result(True, entry_id=entry.id, expires_at=entry.expires_at)

    def _remove_whitelist(self, args: dict, *, decision_id: int) -> dict:
        ok, reason = self.guardrails.check_remove_whitelist(args)
        if not ok:
            return _result(False, blocked=True, reason=reason)
        n = self.whitelist.remove(
            ip=str(args["ip"]).strip(),
            scope=str(args.get("scope", "global")).lower(),
            alert_type=(args.get("alert_type") or None),
        )
        return _result(True, entries_rolled_back=n)

    def _suppress_alert_type(self, args: dict, *, decision_id: int) -> dict:
        ok, reason = self.guardrails.check_suppress(args)
        if not ok:
            return _result(False, blocked=True, reason=reason)
        atype = str(args["alert_type"]).upper()
        hours = int(args.get("duration_hours", 1))
        self.suppressed.suppress(atype, hours)
        return _result(True, alert_type=atype, duration_hours=hours)

    def _unsuppress_alert_type(self, args: dict, *, decision_id: int) -> dict:
        ok, reason = self.guardrails.check_unsuppress(args)
        if not ok:
            return _result(False, blocked=True, reason=reason)
        atype = str(args["alert_type"]).upper()
        changed = self.suppressed.unsuppress(atype)
        return _result(True, alert_type=atype, changed=changed)

    def _run_active_scan(self, args: dict, *, decision_id: int) -> dict:
        ok, reason = self.guardrails.check_scan(args)
        if not ok:
            return _result(False, blocked=True, reason=reason)
        ip = str(args["ip"]).strip()
        scan_type = str(args["scan_type"]).lower()

        if scan_type == "nmap_ports":
            return self._run_nmap_scan(ip)
        if scan_type == "deep_inspect":
            return self._run_deep_inspect(ip)
        return _result(False, blocked=True, reason=f"unhandled scan_type: {scan_type}")

    def _run_nmap_scan(self, ip: str) -> dict:
        nmap = shutil.which("nmap")
        if not nmap:
            return _result(False, reason="nmap binary not found")
        # Args are already validated (ip is an IP literal, no shell metacharacters
        # possible because we pass a list to subprocess and never spawn a shell).
        try:
            cp = subprocess.run(
                [nmap, "-sV", "--open", "-T4", "-p", "1-1024", ip],
                capture_output=True,
                text=True,
                timeout=180,
            )
            return _result(
                True,
                scan_type="nmap_ports",
                ip=ip,
                returncode=cp.returncode,
                stdout_tail=cp.stdout[-2000:],
            )
        except subprocess.TimeoutExpired:
            return _result(False, reason="nmap scan timed out at 180s")

    def _run_deep_inspect(self, ip: str) -> dict:
        nw = shutil.which("netwatchm")
        if not nw:
            return _result(False, reason="netwatchm CLI not found in PATH")
        out_path = f"/tmp/agent-deep-{ip}.html"
        try:
            cp = subprocess.run(
                [nw, "deep-inspect", "--target", ip, "--output", out_path],
                capture_output=True,
                text=True,
                timeout=300,
            )
            return _result(
                True,
                scan_type="deep_inspect",
                ip=ip,
                returncode=cp.returncode,
                output_path=out_path,
                stdout_tail=cp.stdout[-1000:],
            )
        except subprocess.TimeoutExpired:
            return _result(False, reason="deep-inspect timed out at 300s")

    def _send_ntfy_alert(self, args: dict, *, decision_id: int) -> dict:
        ok, reason = self.guardrails.check_notify(args)
        if not ok:
            return _result(False, blocked=True, reason=reason)
        if not self.ntfy or not self.ntfy.enabled or not self.ntfy.topic:
            return _result(False, reason="ntfy not configured")

        severity = str(args["severity"]).upper()
        headline = str(args["headline"])[: self.guardrails.limits.max_headline_chars]
        action_taken = str(args.get("action_taken") or "")
        rationale = str(args.get("reason") or "")
        related_ip = str(args.get("related_ip") or "")
        rollback_entry_id = str(args.get("rollback_entry_id") or "")

        body = self._format_body(severity, action_taken, rationale, related_ip)

        priority_map = {"LOW": "2", "MEDIUM": "3", "HIGH": "4", "CRITICAL": "5"}
        priority = priority_map.get(severity, "3")

        actions_header = self._build_actions_header(
            rollback_entry_id=rollback_entry_id, related_ip=related_ip
        )

        headers = {
            "X-Title": f"[{severity}] NetWatchM agent · {headline[:100]}",
            "X-Priority": priority,
            "X-Tags": "robot",
            "Content-Type": "text/plain",
        }
        if actions_header:
            headers["X-Actions"] = actions_header
        if self.ntfy.token:
            headers["Authorization"] = f"Bearer {self.ntfy.token}"

        url = f"{self.ntfy.server.rstrip('/')}/{self.ntfy.topic}"
        req = urllib.request.Request(
            url, data=body.encode(), headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                status = resp.status
        except urllib.error.URLError as exc:
            return _result(False, reason=f"ntfy POST failed: {exc}")

        return _result(True, ntfy_status=status, severity=severity)

    def _format_body(
        self, severity: str, action_taken: str, rationale: str, related_ip: str
    ) -> str:
        parts: list[str] = []
        if action_taken:
            parts.append(f"Action: {action_taken}")
        if related_ip:
            parts.append(f"IP: {related_ip}")
        if rationale:
            parts.append(f"Why: {rationale}")
        if not parts:
            parts.append("Agent decision recorded.")
        return "\n".join(parts)

    def _build_actions_header(
        self, *, rollback_entry_id: str, related_ip: str
    ) -> str:
        """Build the ntfy X-Actions header for one-tap response from the
        notification.

        - Rollback uses the ``http`` action type so it POSTs silently and
          clears the notification — no browser round-trip.
        - 'Open events' uses ``view`` so it opens the portal in the user's
          browser for further investigation.

        ntfy action syntax:
          http,  Label, URL, method=POST, clear=true
          view,  Label, URL, clear=true
        Actions are semicolon-separated."""
        actions: list[str] = []
        if rollback_entry_id:
            actions.append(
                f"http, Rollback, "
                f"{self.portal_base}/api/agent/rollback/{rollback_entry_id}, "
                f"method=POST, clear=true"
            )
        if related_ip:
            actions.append(
                f"view, Open events, "
                f"{self.portal_base}/events.html?q={related_ip}"
            )
        return "; ".join(actions)
