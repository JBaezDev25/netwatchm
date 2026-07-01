#!/usr/bin/env python3
"""Evaluate prompt tokenization for the NetWatchM agent.

Reports how many tokens a prompt consumes for a given Ollama model, using the
model's own tokenizer via the `/api/chat` `prompt_eval_count` field (run with
`num_predict: 1`, so it tokenizes the prompt without really generating). The
message shape matches what the agent actually sends, so the counts are real.

Usage:
    # the agent's digest prompt (built from the live events.db if readable)
    python3 scripts/count-tokens.py --mode digest

    # the agent's reactive per-tick prompt
    python3 scripts/count-tokens.py --mode reactive

    # an arbitrary string or file
    python3 scripts/count-tokens.py --text "some text to tokenize"
    python3 scripts/count-tokens.py --file /path/to/prompt.txt

    # against a specific events db / model
    python3 scripts/count-tokens.py --mode digest --events-db /var/lib/netwatchm/events.db --model llama3.2:latest

No sudo, read-only. Needs Ollama reachable (default http://localhost:11434).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from netwatchm.config import AgentConfig  # noqa: E402

LIVE_DB = "/var/lib/netwatchm/events.db"


def token_count(messages, model, host):
    body = json.dumps({
        "model": model,
        "messages": messages,
        "stream": False,
        "think": False,
        "options": {"num_predict": 1},
    }).encode()
    req = urllib.request.Request(
        f"{host.rstrip('/')}/api/chat", data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read()).get("prompt_eval_count", 0)


def _synthetic_db():
    """Seed a throwaway events.db so a count is always possible."""
    from datetime import datetime  # noqa: F401
    from netwatchm.alerts.event_store import EventStore
    from netwatchm.models import Alert, ThreatLevel

    db = tempfile.mktemp(suffix=".db")
    def mk(t, l, ip):
        return Alert(alert_type=t, level=l, src_ip=ip, dst_ip="10.0.0.1", description="synthetic event")
    with EventStore(db) as s:
        for _ in range(15):
            s.insert(mk("PORT_SCAN", ThreatLevel.HIGH, "203.0.113.7"))
        s.insert(mk("EXFILTRATION", ThreatLevel.CRITICAL, "10.0.0.50"))
        for _ in range(3):
            s.insert(mk("ADULT_DOMAIN", ThreatLevel.MEDIUM, "10.0.0.31"))
        for _ in range(40):
            s.insert(mk("BEACONING", ThreatLevel.MEDIUM, "10.0.0.22"))
    return db, True


def _resolve_db(events_db):
    if events_db and os.access(events_db, os.R_OK):
        return events_db, False
    if not events_db and os.access(LIVE_DB, os.R_OK):
        return LIVE_DB, False
    return _synthetic_db()


def build_messages(mode, events_db, cfg):
    from netwatchm.agent.agent_loop import SYSTEM_PROMPT_DIGEST, SYSTEM_PROMPT_DRY_RUN

    db, synthetic = _resolve_db(events_db)
    if mode == "digest":
        from netwatchm.agent.digest import build_digest
        d = build_digest(
            events_db_path=db,
            lookback_days=cfg.digest_lookback_days,
            exclude_types=cfg.digest_exclude_types,
            max_events=cfg.digest_max_events,
        )
        user = ("Aggregated alert summary follows:\n\n"
                + json.dumps(d, default=str)[: cfg.context_prompt_char_cap])
        system = SYSTEM_PROMPT_DIGEST
    else:  # reactive
        from netwatchm.agent.context import build_context
        ctx = build_context(
            events_db_path=db,
            config_snapshot={},
            hours_back=cfg.context_hours_back,
            max_events=cfg.context_max_events,
            data_dir=os.path.dirname(db) if not synthetic else None,
        )
        user = ("Snapshot follows. Decide whether anything warrants action. "
                "If unclear, query one or two of your tools, then conclude.\n\n"
                + json.dumps(ctx, default=str)[: cfg.context_prompt_char_cap])
        system = SYSTEM_PROMPT_DRY_RUN

    return system, user, db, synthetic


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["digest", "reactive"])
    ap.add_argument("--text")
    ap.add_argument("--file")
    ap.add_argument("--events-db", default="")
    ap.add_argument("--model", default="mistral:latest")
    ap.add_argument("--host", default="http://localhost:11434")
    args = ap.parse_args()
    cfg = AgentConfig()

    if args.text or args.file:
        text = args.text if args.text else open(args.file).read()
        n = token_count([{"role": "user", "content": text}], args.model, args.host)
        print(f"{n} tokens  ({len(text)} chars)  model={args.model}")
        return

    if not args.mode:
        ap.error("give --mode digest|reactive, or --text/--file")

    system, user, db, synthetic = build_messages(args.mode, args.events_db, cfg)
    # A system message alone isn't tokenized without a user turn, so count the
    # system text as a user message for the standalone figure (role markers add
    # only a couple of tokens).
    sys_n = token_count([{"role": "user", "content": system}], args.model, args.host)
    full_n = token_count(
        [{"role": "system", "content": system}, {"role": "user", "content": user}],
        args.model, args.host,
    )
    src = "synthetic events" if synthetic else db
    print(f"mode={args.mode}  model={args.model}  source={src}")
    print(f"  system prompt : {sys_n:>6} tokens")
    print(f"  full prompt   : {full_n:>6} tokens   ({len(system) + len(user)} chars)")
    if synthetic:
        print("  [note] live events.db not readable — used synthetic data. "
              "Re-run with sudo or --events-db for real numbers.")


if __name__ == "__main__":
    main()
