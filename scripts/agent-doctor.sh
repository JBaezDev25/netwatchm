#!/usr/bin/env bash
# agent-doctor.sh — verify Phase 1 agent wiring without touching production.
#
# What it does:
#   1. Confirms Ollama is reachable and the configured model is available.
#   2. Runs ONE agent decision tick using the live events.db + inventory.json.
#   3. Prints the decision the agent would have recorded (dry-run, never acts).
#   4. Shows the audit DB rows it just wrote to a scratch file (not the live one).
#
# Safe to run repeatedly. Does not modify /etc/netwatchm/netwatchm.yaml, does
# not require sudo, does not restart any service.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# mistral:latest is a 7B non-thinking model — fastest CPU option that still
# does tool calling. qwen3:8b/14b are "thinking" models whose hidden reasoning
# bloats inference time by 5-10x on CPU. Override the default if you have GPU
# acceleration:
#   NETWATCHM_AGENT_MODEL=qwen3:14b bash scripts/agent-doctor.sh
MODEL="${NETWATCHM_AGENT_MODEL:-mistral:latest}"
OLLAMA_URL="${OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
EVENTS_DB="${NETWATCHM_EVENT_DB:-/var/lib/netwatchm/events.db}"
INVENTORY="${NETWATCHM_INVENTORY_FILE:-/var/lib/netwatchm/inventory.json}"
DATA_DIR="${NETWATCHM_DATA_DIR:-/var/lib/netwatchm}"
SCRATCH_AUDIT="/tmp/agent-doctor-audit.db"

echo "==> Agent doctor"
echo "    repo:       $REPO_ROOT"
echo "    model:      $MODEL"
echo "    ollama:     $OLLAMA_URL"
echo "    events.db:  $EVENTS_DB"
echo "    inventory:  $INVENTORY"
echo "    audit out:  $SCRATCH_AUDIT (scratch — not the live audit DB)"
echo

# 1. Ollama reachable?
echo "==> [1/4] Pinging Ollama…"
if ! curl -fsS --max-time 5 "$OLLAMA_URL/api/tags" >/dev/null; then
    echo "   FAIL: $OLLAMA_URL did not respond."
    echo "   Try: ollama serve   (and re-run this script)"
    exit 1
fi
echo "   OK"

# 2. Model present?
echo "==> [2/4] Confirming model '$MODEL' is pulled…"
if ! curl -fsS --max-time 5 "$OLLAMA_URL/api/tags" \
        | grep -q "\"$MODEL\""; then
    echo "   FAIL: model '$MODEL' not found in Ollama."
    echo "   Try: ollama pull $MODEL"
    exit 1
fi
echo "   OK"

# 2b. Pre-warm the model so the first real inference isn't paying the model-load tax.
echo "==> [2b/4] Pre-warming '$MODEL' (loads weights into RAM)…"
if ! curl -fsS --max-time 180 -X POST "$OLLAMA_URL/api/generate" \
        -H "Content-Type: application/json" \
        -d "{\"model\":\"$MODEL\",\"prompt\":\"ok\",\"stream\":false,\"keep_alive\":\"30m\"}" \
        >/dev/null; then
    echo "   WARN: pre-warm call failed or timed out — continuing anyway"
else
    echo "   OK (model resident, kept warm for 30 min)"
fi

# 3. Are there any events to reason about?
echo "==> [3/4] Checking event data…"
if [[ ! -r "$EVENTS_DB" ]]; then
    echo "   WARN: $EVENTS_DB not readable by this user."
    echo "        Tick will still run, but with empty context."
else
    n_events=$(sqlite3 "$EVENTS_DB" \
        "SELECT COUNT(*) FROM events WHERE timestamp >= strftime('%s','now') - 4*3600" 2>/dev/null || echo 0)
    echo "   $n_events events in the last 4 hours"
fi

# Wipe scratch audit so the printout below is just this run
rm -f "$SCRATCH_AUDIT"

# 4. Run one tick
echo "==> [4/4] Running one agent tick (~30-90s on $MODEL after pre-warm,"
echo "          longer on first cold call or with bigger models)…"
echo

cd "$REPO_ROOT"
export PATH="$HOME/.local/bin:$PATH"

uv run python - <<PY
import asyncio
from netwatchm.agent.agent_loop import _run_one_tick
from netwatchm.agent.audit import AuditLog
from netwatchm.agent.llm_client import OllamaClient
from netwatchm.config import AgentConfig, Config

agent_cfg = AgentConfig(
    enabled=True,
    dry_run=True,
    model="$MODEL",
    ollama_base_url="$OLLAMA_URL",
    timeout_seconds=600,
    # Smoke-test caps: shorter prompt + fewer hops so CPU inference finishes in
    # bounded time. Production config can use larger values once the model
    # latency is measured on the deployed hardware.
    context_max_events=15,
    context_prompt_char_cap=4000,
    max_tool_hops=2,
)
client = OllamaClient(
    base_url=agent_cfg.ollama_base_url,
    model=agent_cfg.model,
    timeout=agent_cfg.timeout_seconds,
)

async def main():
    with AuditLog("$SCRATCH_AUDIT") as audit:
        await _run_one_tick(
            agent_cfg=agent_cfg,
            client=client,
            audit=audit,
            events_db_path="$EVENTS_DB",
            inventory_path="$INVENTORY",
            data_dir="$DATA_DIR",
            config_snapshot={"whitelist_ips": [], "detector_whitelist": {}},
        )
        decisions = audit.recent_decisions(limit=1)
        if not decisions:
            print("[agent-doctor] no decision recorded — something went wrong.")
            return
        d = decisions[0]
        print()
        print("=" * 70)
        print(f"  DECISION #{d['id']}  (mode={d['mode']}, events_seen={d['events_seen']}, max_severity={d['max_severity']})")
        print("=" * 70)
        print(d["rationale"] or "(no rationale text returned)")
        print()
        print("--- TOOL CALLS ---")
        calls = audit.calls_for_decision(d["id"])
        if not calls:
            print("  (none — agent returned a final answer without invoking tools)")
        for c in calls:
            print(f"  • {c['tool_name']:30s} status={c['status']:10s} args={c['args_json'][:80]}")
            if c["blocked_reason"]:
                print(f"      blocked_reason: {c['blocked_reason']}")
        if d.get("error"):
            print(f"\nERROR: {d['error']}")

asyncio.run(main())
PY

echo
echo "==> Done."
echo "    Inspect the full scratch audit DB with:"
echo "        sqlite3 $SCRATCH_AUDIT"
echo "        sqlite> .headers on"
echo "        sqlite> SELECT * FROM agent_decisions;"
echo "        sqlite> SELECT * FROM agent_tool_calls;"
