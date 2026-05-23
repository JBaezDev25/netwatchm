"""Autonomous agent package — observes events, decides actions, audits decisions.

Phase 1 (current): dry-run only. The agent builds context, queries the LLM with
read-only tools, and logs proposed decisions to the audit DB. No state-changing
actions are taken.
"""
from .agent_loop import run_agent_loop
from .audit import AuditLog, DEFAULT_AUDIT_DB

__all__ = ["run_agent_loop", "AuditLog", "DEFAULT_AUDIT_DB"]
