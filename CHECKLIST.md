# NetWatchM — Project Checklist

Last updated: 2026-05-24 (session 29)

## Session 29 — 2026-05-24

### Uniform 15-day retention sweep

A background task plus a logrotate drop-in. The text log is rotated by the
OS even when netwatchm is down; everything else is pruned in-process while
the service runs.

#### New module
- [x] `src/netwatchm/retention.py` — `prune_audit_db()` (DELETE + cascade-DELETE + VACUUM on `agent_actions.db`), `compact_whitelist_store()` and `compact_blocks_store()` (rewrite JSON sidecar without rolled-back / expired entries older than retention), `run_retention_loop()` async task (initial sweep at startup + daily cadence), `_sweep_once()` isolates each target so a failure in one doesn't skip the others.

#### Updated existing retention defaults to 15 days
- [x] `src/netwatchm/alerts/event_store.py` — `RETENTION_HOURS: 72 → 360`
- [x] `src/netwatchm/reports/flow_store.py` — `_RETENTION_HOURS: 72 → 360`
- [x] `netwatchm_server.py` — `_RETENTION_DAYS: 30 → 15` (flow-history; pinned entries still kept forever)
- [x] `src/netwatchm/config.py` — `EventStoreConfig.retention_hours: 72 → 360` (dataclass default + YAML loader default)

#### New config knob
- [x] `src/netwatchm/config.py` — new `RetentionConfig` dataclass: `enabled=True`, `retention_days=15`, `interval_seconds=86400`. YAML loader wires it.
- [x] `netwatchm.yaml.example` — new `retention:` block with all three knobs documented (and a note that text-log retention lives in logrotate, not here).

#### Wiring
- [x] `src/netwatchm/__main__.py` — registers `run_retention_loop` as a background task when `config.retention.enabled`. **Always-on**, not gated on `agent.enabled` — retention applies to everyone's logs.

#### Logrotate drop-in
- [x] `scripts/install-log-retention.sh` — installs `/etc/logrotate.d/netwatchm`: daily rotation, `rotate 15`, `compress`, `delaycompress`, `copytruncate` (so the running service keeps its open file descriptor valid through rotation — no SIGHUP needed), runs as `netwatchm:netwatchm`. Script auto-creates `/var/log/netwatchm/` if missing, validates the drop-in with `logrotate --debug`, and idempotently overwrites on re-run. Rollback: `sudo rm /etc/logrotate.d/netwatchm`.

#### Tests
- [x] `tests/test_retention.py` — 10 new tests: audit prune removes old + cascades tool calls, prune is a no-op when nothing old, prune handles missing file; whitelist compact removes old rolled-back, keeps old-but-active, handles missing file; blocks compact removes old rolled-back + old expired; `run_retention_loop` does initial sweep at startup and stops cleanly; defaults are 15 days.
- [x] **306 tests pass** (was 296 → +10 new).

#### Promotion path (manual, when ready)
```bash
# 1. Install the logrotate drop-in (one-time, system-level)
sudo bash scripts/install-log-retention.sh

# 2. Deploy the code so the in-process retention task starts running
bash scripts/deploy-server.sh        # system venv update
sudo systemctl restart netwatchm     # main monitor picks up retention loop
sudo systemctl restart netwatchm-web # web server picks up new retention defaults

# 3. Verify the retention loop registered
journalctl -u netwatchm --since "1 min ago" | grep -i "retention"
# expect: "retention loop starting (retention=15d, interval=86400s)"

# 4. (Optional) Force the first sweep without waiting 24h by restarting
# the service — the loop always sweeps once at startup.
```

#### What this does NOT touch
- `inventory.json` — keeps its 48 h stale-device cleanup (different semantic from log retention).
- ntfy notifications history (server-side at ntfy.sh, out of our control).
- The OS journal (`journalctl -u netwatchm`) — already managed by systemd's own `journald` config.

---

## Session 28 — 2026-05-23

### Phase 5 — Firewall mitigation (auto-expiring ufw blocks)

Built and tested. Not deployed live — promotion path is the same as Phase 2:
review behaviour, then flip into live mode.

#### New module
- [x] `src/netwatchm/agent/firewall.py` — `BlockEntry` dataclass + `FirewallStore` (JSON sidecar at `/var/lib/netwatchm/agent_blocks.json`, append + soft-delete, atomic .tmp+rename writes) + `FirewallController` (validates IP/port in Python before subprocess, calls `sudo ufw deny from <ip> [to any port <p>]` and `sudo ufw delete deny from …`, treats "Could not delete non-existent rule" as soft success) + `run_firewall_reaper` async task that scans every 60s for expired entries, removes them from ufw, marks the store rolled-back, and audits the removal as a `__reaper__` tool call. Runs independently of the agent tick so TTLs are enforced even if the LLM call is stuck.

#### Guardrails extension
- [x] `src/netwatchm/agent/guardrails.py` — added `check_block` and `check_remove_block` methods. Hard refuses (in order): malformed IP, CIDR, RFC1918/loopback/link-local, gateway, host IPs, global whitelist, port 22, port out of range, non-tcp/udp protocol, duration outside [1, 1440] minutes, empty `reason`, active-blocks ceiling (10), hourly rate cap (5 add+remove). `Guardrails.__init__` gained `firewall_store`, `global_whitelist_ips`, `gateway_ips`, `host_ips` (all default empty/None so existing call sites keep working). New module-level helper `detect_host_network_info()` reads `ip route show default` + `ip -o addr show` via subprocess and returns gateway/host IP lists for runtime injection.
- [x] `GuardrailLimits` gained: `max_block_changes_per_hour=5`, `max_active_blocks=10`, `max_block_minutes=1440`, `default_block_minutes=60`, `banned_block_ports=frozenset({22})`, `allowed_block_protocols=frozenset({"tcp","udp"})`.

#### Executor + tools + system prompt
- [x] `src/netwatchm/agent/executor.py` — two new dispatch entries `add_temporary_block` and `remove_block`. Guardrails check → ufw subprocess → store write → structured result. Constructor gained optional `firewall_store` + `firewall_controller`; if either is None the dispatch returns blocked with "firewall executor not configured on this host". `_send_ntfy_alert` + `_build_actions_header` now also forward `unblock_entry_id` so ntfy notifications carry both Rollback (whitelist) and Unblock (firewall) one-tap action buttons.
- [x] `src/netwatchm/agent/tools.py` — added `add_temporary_block` and `remove_block` to `ACTION_TOOL_SCHEMAS`. `send_ntfy_alert` schema gained an `unblock_entry_id` property next to the existing `rollback_entry_id`.
- [x] `src/netwatchm/agent/agent_loop.py` — `SYSTEM_PROMPT_LIVE` updated: severity guide now describes when to use `add_temporary_block` (HIGH external IPs, CRITICAL with strong evidence). `run_agent_loop` now constructs `FirewallStore`+`FirewallController`+`detect_host_network_info()` in live mode and passes them to Guardrails + Executor.

#### Wiring + background task
- [x] `src/netwatchm/__main__.py` — when `config.agent.enabled` AND NOT `config.agent.dry_run`, the firewall reaper is registered as a separate asyncio task alongside the agent loop. Reaper runs every 60s.

#### Web UI + endpoints
- [x] `netwatchm_server.py` — `GET /api/agent/blocks` (active blocks JSON) + `POST /api/agent/unblock/<id>` (capability-bearer pattern: the entry_id is only surfaced via ntfy notification the user controls, so possessing it = authorized; same model as `/api/agent/rollback/`). Unblock both marks the store rolled-back AND calls ufw to remove the live rule.
- [x] `firewall.html` (new, repo root) — dark-theme SPA: active-block count, sortable table (IP, port, protocol, added, expires, TTL countdown, reason, Unblock button), 30s auto-refresh with countdown, confirmation dialog before unblock. Nav links to events/inventory/history/firewall/AI.
- [x] `scripts/hotdeploy.sh` — extended from 3 → 4 steps so `firewall.html` is copied to `/var/lib/netwatchm/` alongside `ai.html` and `netwatchm_server.py`.

#### Sudoers drop-in
- [x] `scripts/install-firewall-sudoers.sh` — installs `/etc/sudoers.d/netwatchm-firewall` granting the `netwatchm` user NOPASSWD on **exactly five** ufw subcommand shapes: `deny from *`, `deny from * to any port *`, `delete deny from *`, `delete deny from * to any port *`, `status numbered`. Validates with `visudo -cf` against the tmp copy AND against the full system sudoers after install. Smoke-tests that `sudo -u netwatchm sudo -n ufw status numbered` works. Idempotent; rollback = `sudo rm /etc/sudoers.d/netwatchm-firewall`.

#### Tests
- [x] `tests/test_agent_firewall.py` — **40 new tests** covering: guardrails refusal cases (RFC1918, loopback, link-local, CIDR, gateway, host IP, global whitelist, port 22, port OOB, bad protocol, duration cap, empty reason, active-blocks ceiling, rate cap), guardrails clean-input acceptance, `check_remove_block` allows RFC1918 for cleanup, FirewallStore (persistence, expired_active, active_entries excludes expired+rolled_back, mark_rolled_back idempotency, corrupted-file fallback), FirewallController (subprocess argv shape add/remove with/without port, shell-injection rejection in IP, port OOB rejection, soft-ok on "Could not delete non-existent rule"), reaper (removes only expired, marks rolled_back even on ufw failure), executor dispatch (happy path, blocked-by-guardrails, ufw-failure returns error not blocked, remove happy path), tool schema sanity, ntfy schema includes `unblock_entry_id`, `detect_host_network_info` smoke test.
- [x] Updated `tests/test_agent_phase2.py::test_action_tool_schemas_well_formed` to include the two new action tool names.
- [x] **All 296 tests pass** (was 256 → +40 new).

#### Promotion path (manual, when ready)
```bash
# 1. Install the sudoers drop-in (one time)
sudo bash scripts/install-firewall-sudoers.sh

# 2. Deploy the new code + UI
bash scripts/deploy-server.sh     # netwatchm_server.py + system venv + restart web
bash scripts/hotdeploy.sh         # also pushes firewall.html
sudo systemctl restart netwatchm  # main monitor picks up new agent code

# 3. Verify the firewall reaper task started (live mode only)
journalctl -u netwatchm --since "1 min ago" | grep -i "firewall reaper"

# 4. Visit https://localhost:8765/firewall.html — should show "No active blocks"
```

#### Code-only deploy executed 2026-05-23 19:40 EDT
- [x] Sudoers drop-in installed (`/etc/sudoers.d/netwatchm-firewall`, visudo OK, `netwatchm` user smoke-test passed).
- [x] `deploy-server.sh` ran — system venv updated with Phase 5 agent code, `netwatchm-web` restarted (pid 429281 → 429310 after hotdeploy).
- [x] `hotdeploy.sh` ran — `firewall.html` copied to `/var/lib/netwatchm/`.
- [x] `netwatchm` main monitor restarted at 19:40:10 (pid 429321). Agent loop log: `agent loop starting (model=mistral:latest, interval=300s, mode=dry_run, executor=off)`. **No import errors / tracebacks** — Phase 5 imports work.
- [x] Verified: `GET /api/agent/blocks` returns `{"entries": []}`; `/firewall.html` serves the SPA; firewall reaper task NOT registered (correct — `dry_run` is still true); decision id=29 in flight on first post-restart tick.

#### Out-of-scope (deliberately)
- iptables/nftables backend (ufw only — already used by `enable-remote-access.sh`)
- Process termination (too broad blast radius — ntfy + manual kill)
- Service restart/isolation (same reason)
- CIDR-scoped blocks (only single-IP literals accepted)
- Port-only blocks without an IP target (would require a whole new policy model)

---

## Session 27 — 2026-05-23

### Operator helper: enable agent in dry-run safely
- [x] `scripts/enable-agent-dryrun.sh` — flips live `/etc/netwatchm/netwatchm.yaml` to `agent.enabled: true` while forcing `agent.dry_run: true`. Uses system venv's PyYAML for structured edit (preserves model/intervals/caps). Shows unified diff + y/N prompt, timestamped backup, restart `netwatchm`, then tails `journalctl` for agent/ollama lines. Refuses to run if live config already has `dry_run: false` (would be promotion to live actions — out of scope for this helper).
- [x] Verified edit logic against `netwatchm.yaml.example` and `bash -n` syntax check.
- [x] **State observation** — live `netwatchm` service was started 2026-05-18 (5 days before Session 26's commit), `agent_actions.db` does not exist → agent never ran. Promotion sequence: `bash scripts/deploy-server.sh` → `bash scripts/enable-agent-dryrun.sh` → watch audit DB for a day or two → only then flip `dry_run: false` separately.
- [x] **Step 1 — `deploy-server.sh` executed** (2026-05-23 14:14 EDT). System venv refreshed to Session 26 code; `netwatchm_server.py` copied; `netwatchm-web` restarted as PID 322087. Verified `/api/agent/decisions` returns `{"decisions": []}` (route present, audit DB empty as expected). Ollama reachable on 127.0.0.1:11434 with `mistral:latest` available. **Main `netwatchm` monitor service NOT yet restarted** — that happens in step 2 via `enable-agent-dryrun.sh`.
- [x] **Step 2 — `enable-agent-dryrun.sh` executed** (2026-05-23 14:18 EDT). Live YAML had no `agent:` block previously — PyYAML edit appended `agent: { enabled: true, dry_run: true }` (other keys fall back to AgentConfig dataclass defaults). Backup at `/etc/netwatchm/netwatchm.yaml.bak-20260523-141833`. Service restarted; journal confirms: `agent loop starting (model=mistral:latest, interval=300s, mode=dry_run, executor=off)`. First decision expected in audit DB ~14:24–14:25 EDT (5-min tick interval + CPU inference).
- [x] **Diagnosed Ollama hang on first two ticks** — both decisions id=1,2 errored at hop 0 (`timed out` / `Remote end closed`). Root cause in `journalctl -u ollama`: `failure during GPU discovery — OLLAMA_LIBRARY_PATH=[…/cuda_v13] error="failed to finish discovery before timeout"`. Ollama deadlocked enumerating a CUDA backend that doesn't exist on this Ryzen 5 5600G (CPU-only). `sudo systemctl restart ollama` cleared it; mistral now responds in 3.3s (load_duration 2.34s + eval ~11 tok/s) — matches Session 25's CPU baseline.
- [x] **Hardening script written** — `scripts/harden-ollama-cpu-only.sh`. Drops `Environment=OLLAMA_NUM_GPU=0` + `CUDA_VISIBLE_DEVICES=""` + `HIP_VISIBLE_DEVICES=""` into `/etc/systemd/system/ollama.service.d/no-gpu.conf`. `OLLAMA_NUM_GPU=0` alone wouldn't stop discovery (it only controls layer count); the CUDA/HIP visibility env vars are what actually hide the runtimes from Ollama's discovery code. Daemon-reloads, restarts ollama, then times a trivial chat request to confirm. Idempotent; rollback = delete the drop-in file. **Run with `sudo bash scripts/harden-ollama-cpu-only.sh`.**
- [x] **First successful agent tick** — decision id=4 at 14:53:03 EDT completed with 1062-char rationale (~6.5 min for the tick on this CPU; `events_seen=24`, max_severity=HIGH). Mistral summarised the context but did not call any read-only tools — a known weakness of small instruct models with native tool calling. Even bare LLM reasoning is enough information for Phase 1 dry-run review.
- [x] **Ntfy push watcher** — `scripts/agent-watcher.sh`: polls `agent_actions.db` every 30s, pushes a notification to topic `netwatchm-abc123` for each newly completed decision (one-shot per id via `/tmp/agent-watcher.last_id` state). Severity → ntfy priority map (CRITICAL=5, HIGH=4, MEDIUM=3, LOW=2). Subcommands: `--once`, `--foreground`, `--daemon` (nohup → `/tmp/agent-watcher.log`), `--status`, `--stop`. **Bug found + fixed** during dev: rationale text can contain newlines (markdown lists), which split `while read` rows; SQL now flattens `char(10)` / `char(13)` / `|` to spaces before output. Daemon started 2026-05-23 15:16 EDT (pid recorded in `/tmp/agent-watcher.pid`).
- [ ] **Step 3 — observe dry-run decisions for a day or two** then decide whether judgment looks sound enough to flip `dry_run: false`. Each tick ~6 min on CPU; interval=300s means near-continuous ticks. If a tick errors with `events_seen` ≥ 40, drop `agent.context_max_events: 50 → 15` to stay within mistral's CPU budget (per Session 25 `agent-doctor.sh` defaults). Watch query: `sqlite3 /var/lib/netwatchm/agent_actions.db 'SELECT datetime(ts,"unixepoch","localtime"), max_severity, substr(rationale,1,80) FROM agent_decisions ORDER BY ts DESC LIMIT 20'`.
- [x] **Committed + pushed Sessions 27-28 to GitHub** — single commit `9890718` ("Sessions 27-28: dry-run rollout helpers + Phase 5 firewall mitigation"), rebased onto CI's v0.2.37 version bump and pushed to origin/master. 17 files, 2103 insertions / 20 deletions.

---

## Session 26 — 2026-05-23

### Autonomous agent — Phase 2 (live action mode + guardrails)
- [x] `src/netwatchm/agent/guardrails.py` — `Guardrails` class with `GuardrailLimits` dataclass. Hard programmatic limits the LLM cannot override: refuses whitelist of 0.0.0.0/unspecified/multicast/reserved, IPs with recent CRITICAL alerts, CIDR ranges. Refuses suppression of CRITICAL alert types (EXFILTRATION, MALWARE_DOMAIN). Caps suppression at 24h, whitelist TTL at 72h, notify headlines at 200 chars. Rate caps: 5 whitelist changes/hr, 3 suppress changes/hr, 10 scans/hr, 20 notifications/day — counted via SQLite query on `agent_tool_calls` audit table.
- [x] `src/netwatchm/agent/state.py` — two side-car state stores:
  - `AgentWhitelistStore` writes to `/var/lib/netwatchm/agent_whitelist.json` (TTL-bounded, soft-delete rollback, atomic file replace)
  - `SuppressedTypesStore` extends the existing `suppressed.json` schema with a `ttl` map for agent-added entries (legacy `types` list still honoured)
- [x] `src/netwatchm/__main__.py` — `alert_dispatch_loop` now hot-reloads `agent_whitelist.json` (5s cache, same pattern as suppressed.json) and skips alerts matching active agent whitelist entries before scoring/handlers — additions take effect without service restart
- [x] `src/netwatchm/agent/executor.py` — `Executor` class with 6 action tools: `add_whitelist_entry`, `remove_whitelist_entry`, `suppress_alert_type`, `unsuppress_alert_type`, `run_active_scan` (nmap_ports / deep_inspect), `send_ntfy_alert`. Every action: guardrails check → mutation → structured result. Scans spawned as subprocess list (no shell, no metacharacter injection). ntfy POST includes `X-Actions` header with one-tap `Rollback` (http POST) + `Open events` (view) action buttons
- [x] `src/netwatchm/agent/tools.py` — `ACTION_TOOL_SCHEMAS` (6 schemas) added alongside read-only `TOOL_SCHEMAS`
- [x] `src/netwatchm/agent/agent_loop.py` — split `SYSTEM_PROMPT` into `SYSTEM_PROMPT_DRY_RUN` and `SYSTEM_PROMPT_LIVE`; the live prompt instructs the model on severity-weighted action selection (LOW → whitelist, HIGH → scan+notify, CRITICAL → deep_inspect+notify, never whitelist). `_run_one_tick` routes action tool calls through the executor when not dry-run; even fabricated action tool calls in dry-run mode are logged as `blocked`. `run_agent_loop` builds Guardrails + Executor when live mode is active
- [x] `netwatchm_server.py` — three new endpoints:
  - `GET /api/agent/decisions?limit=N` — recent decisions
  - `GET /api/agent/decisions/<id>/calls` — tool calls for one decision
  - `GET /api/agent/whitelist` — active agent whitelist entries
  - `POST /api/agent/rollback/<entry_id>` — roll back a whitelist entry (no admin token — the entry_id is a capability bearer that only surfaces via the ntfy notification the user controls)
- [x] `src/netwatchm/config.py` — `AgentConfig` defaults updated: `model: mistral:latest` (fastest tool-capable CPU model), `timeout_seconds: 600`
- [x] `netwatchm.yaml.example` — `agent:` block reworded to describe both Phase 1 (dry-run) and Phase 2 (live) modes
- [x] `tests/test_agent_phase2.py` — 31 new tests: guardrails (arg shape, recent CRITICAL block, TTL caps, banned types), rate caps (whitelist/scan/notify), state file CRUD + TTL expiry + rollback, suppression TTL cleanup, executor happy paths + blocked-by-guardrails paths + unknown-tool refusal + scan args validated before subprocess + ntfy posts with action buttons + ntfy blocked when not configured, prompt-injection regression (attacker text in description cannot bypass guardrails), schema sanity
- [x] **All 256 tests pass** (was 225 → +31 new)

### Safety invariants enforced in Phase 2
- Guardrails are evaluated **server-side in Python** for every action — the LLM cannot bypass them by rephrasing
- Refuses to whitelist any IP that fired CRITICAL in last 24h (configurable lookback)
- Refuses to suppress CRITICAL severity alert types regardless of duration
- Whitelist entries are TTL-bounded (default 24h, cap 72h) — auto-expire even if forgotten
- Rate limits are hard, counted from the audit DB — burst protection survives a runaway loop
- Scan subprocess spawned with list args (no shell), IP literal validated by `ipaddress.ip_address()` first
- ntfy rollback button uses HTTP POST action type — one tap on the phone rolls back without browser round-trip
- Even in dry-run mode, fabricated action tool calls are recorded as `blocked` (defense in depth)

### How to promote from Phase 1 to Phase 2 (manual — same caveat about deploy-server.sh first)
1. Review recent dry-run decisions: `sqlite3 /var/lib/netwatchm/agent_actions.db 'SELECT ts, max_severity, rationale FROM agent_decisions ORDER BY ts DESC LIMIT 20'`
2. If judgment looks sound, flip `agent.dry_run: false` in `/etc/netwatchm/netwatchm.yaml`
3. Ensure `alerts.ntfy.enabled: true` and topic configured (or notifications will be blocked)
4. `bash scripts/deploy-server.sh && sudo systemctl restart netwatchm`
5. Watch the audit log for the first few live actions; tap Rollback on the ntfy notification if any whitelist add looks wrong

---

## Session 25 — 2026-05-23

### Agent doctor + LLM client — CPU-inference tuning
- [x] `scripts/agent-doctor.sh` — added `[2b/4] Pre-warming` step that POSTs to `/api/generate` with `keep_alive=30m` so the first real inference doesn't pay the model-load tax; bumped client timeout to 600s
- [x] `scripts/agent-doctor.sh` — default model switched `qwen3:14b` → `qwen3:8b` → `mistral:latest`. Mistral 7B is a non-thinking model that responds reliably under 60s on this Ryzen 5 5600G (CPU only), whereas Qwen3 spends most of its generation budget on hidden reasoning. Env override: `NETWATCHM_AGENT_MODEL=qwen3:14b bash scripts/agent-doctor.sh`
- [x] `scripts/agent-doctor.sh` — smoke-test caps tightened: `context_max_events=15`, `context_prompt_char_cap=4000`, `max_tool_hops=2` so an LLM call completes in bounded time on CPU
- [x] `src/netwatchm/agent/llm_client.py` — `OllamaClient.chat()` now sends `think: false` by default, which disables Qwen3/DeepSeek-R1 reasoning-trace mode. Without this, the model pours all output into a separate `thinking` field and leaves `content` empty, making it appear to hang from the caller's perspective
- [x] `src/netwatchm/agent/llm_client.py` — generation capped at `max_tokens=512` (Ollama `num_predict`); production callers can pass a larger value if needed
- [x] **All 20 agent tests still pass** (LLM is mocked, so behaviour-preserving for tests; verified against live Ollama via diagnostic curl)

### Root-cause notes for future debugging
- Ollama timing fields per response: `prompt_eval_count`/`prompt_eval_duration` = prompt processing speed; `eval_count`/`eval_duration` = generation speed. On Ryzen 5 5600G no-GPU: qwen3:8b runs at ~14 prompt-tok/s and ~3 gen-tok/s. Use these to predict whether a model can finish one tick under timeout.
- Symptom "(no rationale text returned)" + `__llm__ status=error blocked_reason: timed out` = urllib timeout fired before Ollama responded. Either model is too slow for the prompt size, or thinking-mode is consuming the entire generation budget. Disable thinking first; switch model second; shrink prompt third.

---

## Session 24 — 2026-05-22

### Autonomous agent — Phase 1 (dry-run, local Ollama)
- [x] `src/netwatchm/agent/` — new package: `__init__.py`, `audit.py`, `context.py`, `llm_client.py`, `tools.py`, `agent_loop.py`
- [x] `src/netwatchm/agent/audit.py` — append-only `agent_actions.db` (WAL mode); two tables: `agent_decisions` + `agent_tool_calls` with status field as the only mutable column
- [x] `src/netwatchm/agent/context.py` — builds per-tick snapshot from events.db + inventory.json + aliases.json + verified.json + suppressed.json + policy; wraps all packet-derived text in `<untrusted>` tags with control-char stripping + tag-delimiter scrubbing; normalises inventory.json list-vs-dict shapes
- [x] `src/netwatchm/agent/llm_client.py` — `OllamaClient` using stdlib urllib only; targets `/api/chat` with native tool calling
- [x] `src/netwatchm/agent/tools.py` — 5 read-only context tools: `query_recent_events`, `query_threat_history`, `query_device_inventory`, `query_whitelist_state`, `query_suppression_state`; tool dispatcher rejects unknown names; `_require_ip` validates IPv4/IPv6 literals (blocks shell-metacharacter argument injection)
- [x] `src/netwatchm/agent/agent_loop.py` — async dry-run loop, tool-hop limit, every decision + every tool call written to audit DB; LLM call runs via `asyncio.to_thread` so it doesn't block the main loop
- [x] `src/netwatchm/config.py` — `AgentConfig` dataclass (defaults: `enabled=False, dry_run=True, model=qwen3:14b, interval_seconds=300, max_tool_hops=4`); YAML loader wiring
- [x] `src/netwatchm/__main__.py` — `run_monitor()` registers the agent task when `config.agent.enabled`; resolves `NETWATCHM_EVENT_DB` / `NETWATCHM_INVENTORY_FILE` env overrides
- [x] `netwatchm.yaml.example` — new `agent:` block with all knobs commented (disabled by default)
- [x] `tests/test_agent.py` — 20 new tests: audit schema + status transitions, sanitiser invariants (control chars / tag delimiters / truncation / None), context summarisation + untrusted-tag wrapping, tool dispatcher rejecting unknown names + bad IPs, end-to-end dry-run tick with stubbed LLM, disabled-agent fast return, LLM-error path
- [x] **All 225 tests pass** (was 205 → +20 new)

### Safety properties enforced in Phase 1
- Append-only audit: decisions never mutated, tool-call status the only writable field
- Prompt-injection defence: attacker-controlled text wrapped in `<untrusted>` with delimiter scrubbing; system prompt instructs LLM to ignore embedded commands
- Argument validation: IPs must parse via `ipaddress.ip_address()`, integers range-checked
- Dispatcher allow-list: only the 5 declared tools execute; unknown names refused
- Dry-run hard wired: no action tools exist yet — even a fabricated tool call would be rejected at dispatch

### Verify wiring without enabling (safe, no service restart)
- [x] `scripts/agent-doctor.sh` — pings Ollama, confirms model is pulled, runs ONE agent tick against the live `events.db`/`inventory.json`, prints the decision the agent recorded to a scratch audit DB at `/tmp/agent-doctor-audit.db`. Does not touch `/etc/netwatchm/netwatchm.yaml` or restart any service. Safe to re-run.

### How to enable (manual — agent is disabled by default)
```bash
# 1. Ensure ollama serves qwen3:14b (already pulled — confirmed via `ollama list`)
ollama serve &
# 2. Flip enabled: true in /etc/netwatchm/netwatchm.yaml under the agent: block
# 3. Restart the monitor: sudo systemctl restart netwatchm
# 4. Watch the audit DB: sqlite3 /var/lib/netwatchm/agent_actions.db 'SELECT * FROM agent_decisions ORDER BY ts DESC LIMIT 5'
```

Note: first tick after enable will be slow (~30-60s) while Ollama loads the model into RAM on CPU. Subsequent ticks should complete in ~10-20s with qwen3:14b on this Ryzen 5 5600G (no GPU acceleration). `timeout_seconds` default is 120s.

### Pending — promote to live actions only after dry-run review
- [x] Phase 2 — guardrails module + action executor + ntfy action buttons (whitelist mod, suppress, scan, notify) → **delivered in Session 26**
- [ ] Phase 3 — additional context sources (DNS query history, ufw firewall rules, nmap -O OS fingerprints, per-IP bandwidth aggregator)
- [ ] Phase 4 — `/agent.html` decisions history page. The override + one-click rollback portion of the original Phase 4 is **already covered**: `/firewall.html` (Session 28) lists active blocks with Unblock buttons, and the ntfy notifications carry Rollback actions for whitelist entries (Session 26). Only the historical-decisions viewer over `agent_decisions` is still missing.

---

## Session 23 — 2026-05-08

### Three new detectors: DNS Tunneling, C2 Beaconing, Malware Domain
- [x] `src/netwatchm/config.py` — added `MalwareDomainConfig`, `DnsTunnelingConfig`, `BeaconingConfig` dataclasses + YAML loader wiring (defaults: malware refresh every 6h, dns_tunneling 10 queries/60s, beaconing 6 contacts with <15% jitter)
- [x] `src/netwatchm/detector/malware_domain.py` — `MalwareDomainDetector` (HIGH). Clones the AdultDomain pattern; default feed = abuse.ch URLhaus host file; per-(src_ip, domain) dedup with 30-min cooldown; `domain_set` test injection
- [x] `src/netwatchm/detector/dns_tunneling.py` — `DnsTunnelingDetector` (HIGH). Per-src_ip sliding window of suspicious queries; suspicious = long FQDN OR long leftmost label OR high Shannon entropy in leftmost label; alerts after N suspicious queries within window
- [x] `src/netwatchm/detector/beaconing.py` — `BeaconingDetector` (HIGH). Per-(src_ip, dst_ip) outbound contact log; computes mean interval + coefficient of variation; alerts when ≥min_contacts, mean in `[min_interval, max_interval]`, and CoV < max_jitter_ratio. 1s connection-folding so a single TCP flow doesn't inflate contact count
- [x] `src/netwatchm/detector/__init__.py` — exports new detectors
- [x] `src/netwatchm/__main__.py` — instantiates the three new detectors in `run_monitor()` after the existing domain detectors
- [x] `tests/conftest.py` — imports of new config dataclasses
- [x] `tests/test_detectors.py` — 31 new tests across `TestMalwareDomainDetector` (10), `TestDnsTunnelingDetector` (10), `TestBeaconingDetector` (11). Beaconing tests inject historical timestamps directly into `_contacts[key]` to avoid waiting real wall-clock minutes
- [x] `netwatchm.yaml.example` — three new `thresholds.*` sections + new alert types listed in `detector_whitelist` comment
- [x] **All 205 tests pass** (was 174 → +31 new)

### Coverage added (mapped to user categories)
- **Malware Indicators** → `MALWARE_DOMAIN` alert via URLhaus feed
- **DNS Tunneling** → `DNS_TUNNELING` alert (long/high-entropy DNS query bursts)
- **C2 Server Connection** → `BEACONING` alert (periodic outbound contacts)

### Deploy command (session 23)
```bash
bash scripts/deploy-server.sh   # reinstall netwatchm package with new detectors + restart
```

### Evidence-gathering script for 192.168.1.180 → 142.251.163.83 investigation
- [x] `scripts/investigate-192-168-1-180.sh` — gathers events, flows, inventory, DNS/WHOIS, log slice + runs deep-inspect into `/tmp/investigate-192.168.1.180/`. Self-sudoing where needed.
- [x] **Investigation result** — destination `142.251.163.83` (PTR `wv-in-f83.1e100.net`) is benign Google service traffic. The 5 BEACONING alerts on 2026-05-08 19:30-19:54 from 192.168.1.180 fan out to Google + Cloudflare/Discord (`162.159.140.33`) + AWS CloudFront — ~45s heartbeat fingerprint of desktop SaaS apps (Discord, Workspace, etc.), not C2.

### Detector tuning — silence monitor-host self-noise from new detectors
- [x] `scripts/whitelist-monitor-beacon.sh` — programmatically adds `192.168.1.180` to `detector_whitelist.BEACONING` and `detector_whitelist.TRACKER_DOMAIN` in live config (`/etc/netwatchm/netwatchm.yaml`), shows a diff, prompts before applying, backs up, and restarts `netwatchm`. Uses the system venv's PyYAML for safe in-place YAML edit.

---

## Session 22 — 2026-04-23

### Fix `ModuleNotFoundError: No module named 'netwatchm'` in system venv
- [x] **Root cause** — `scripts/deploy-server.sh` step 2 used `pip install -e "$REPO"` for the system venv at `/usr/local/lib/netwatchm/venv`. The editable install dropped a `.pth` file pointing at `/home/jbaez120/ai-projects/netwatchm/src`. After session 16 hardening switched the service to the `netwatchm` system user, that user cannot traverse `/home/jbaez120` (mode `0750`, `netwatchm` not in `jbaez120` group) — so `import netwatchm` fails inside the venv CLI script.
- [x] `scripts/deploy-server.sh` — step 2 now uninstalls any prior `netwatchm` install in the system venv and runs a non-editable `pip install "$REPO"`, which copies the package into `site-packages/` so the `netwatchm` user can read it without home-dir access. Added an explanatory comment so this regression doesn't return.

### Deploy command (session 22)
```bash
bash scripts/deploy-server.sh   # reinstalls netwatchm into system venv non-editably + restart
```

---

## Session 21 — 2026-04-18

### Email alerts — frequency + content fixes
- [x] `src/netwatchm/alerts/email_alert.py` — cooldown key changed from `alert_type` to `(alert_type, src_ip)`: each device has its own per-type cooldown, so a busy device no longer blocks alert emails from other devices
- [x] `src/netwatchm/alerts/email_alert.py` — default `cooldown_seconds` raised from 300s → 3600s (1 hour per device per alert type)
- [x] `src/netwatchm/alerts/email_alert.py` — email subject now includes device alias or IP: `[NetWatchM] HIGH · My Laptop — Network scan detected`
- [x] `src/netwatchm/alerts/email_alert.py` — email body: alert type code shown as badge (e.g. `PORT_SCAN`), device alias resolved from aliases.json, "View events for this device" portal link added
- [x] `src/netwatchm/config.py` — `EmailAlertConfig.cooldown_seconds` default updated to 3600
- [x] `netwatchm.yaml.example` — `email.cooldown_seconds` updated to 3600 with updated comment
- [x] `scripts/fix-email-cooldown.sh` — updates live config cooldown to 3600 + restarts `netwatchm`

### Deploy commands (session 21)
```bash
bash scripts/fix-email-cooldown.sh   # update live cooldown + restart netwatchm
bash scripts/deploy-server.sh        # reinstall netwatchm package with new email code
```

---

## Session 20 — 2026-04-15

### Detector whitelist — suppress monitor host false positives
- [x] `/tmp/netwatchm-updated.yaml` — `PORT_SCAN` and `DATA_HOG` detector_whitelist entries added for `192.168.1.180`; `ADULT_DOMAIN` was already suppressed for that IP; `BRUTE_FORCE`/`EXFILTRATION`/`TOR_EXIT` remain active
- [x] `scripts/suppress-monitor-host.sh` — backs up live config, applies update, restarts `netwatchm`
- [x] **Run**: applied manually — `sudo cp /tmp/netwatchm-updated.yaml /etc/netwatchm/netwatchm.yaml && sudo systemctl restart netwatchm`

### Windows installer — private repo fix (bundled source)
- [x] `netwachmInstall/installer_gui.py` — detects PyInstaller bundle via `sys._MEIPASS`; extracts from embedded `netwatchm-src.zip` instead of downloading from GitHub (private repo = 404)
- [x] `netwachmInstall/installer.spec` — embeds `netwatchm-src.zip` in PyInstaller bundle when the file exists (generated in CI, not committed)
- [x] `.github/workflows/release.yml` — new step before PyInstaller build: creates `netwatchm-bundled/` with src/, netwatchm_server.py, pyproject.toml, netwatchm.yaml.example + zips to `netwatchm-src.zip`
- [x] `.gitignore` — added `netwachmInstall/netwatchm-src.zip` and `netwachmInstall/netwatchm-bundled/` (CI-generated, not checked in)
- [ ] **Windows install test** — download `netwatchm-setup.exe` from GitHub Releases v0.2.34, install on Windows machine, verify end-to-end

---

## Session 19 — 2026-04-15

### Dark/Light theme — inventory + history pages
- [x] `netwatchm_server.py` — inventory page: `[data-theme="light"]` CSS variables + ☀ toggle button in toolbar + theme JS with localStorage persistence
- [x] `netwatchm_server.py` — history page: `[data-theme="light"]` CSS variables + ☀ toggle button in nav + theme JS with localStorage persistence
- [x] Theme preference shared via `localStorage('nwm-theme')` — same key used by events portal, so switching theme on any page persists across all pages

### Grafana — CRITICAL Exfiltration alert endpoint
- [x] `netwatchm_server.py` — `_query_exfiltration_count()`: counts EXFILTRATION events in last 24h
- [x] `netwatchm_server.py` — `/api/alerts/exfiltration` endpoint added to GrafanaHandler; `setup-grafana-alerts.sh` already references it — was missing server-side

### Role-based access — events portal
- [x] `netwatchm_server.py` — `GET /api/auth/whoami`: returns `{"role":"admin"|"reader"|"guest"}` based on `X-Admin-Token` / `X-Read-Token` headers
- [x] `netwatchm_server.py` — events portal: login modal with token input; token stored in `sessionStorage` (persists page refresh, clears on tab close); calls `/api/auth/whoami` to resolve role
- [x] `netwatchm_server.py` — role badge in topbar: 🔒 Admin (green) | 👁 Read-only (blue) | 👤 Guest (grey)
- [x] `netwatchm_server.py` — admin-only buttons (Clear Alerts, Suppressions, Test Notify) hidden for Guest/Reader; revealed on admin login; Logout button replaces Login

### Documentation
- [x] `CHECKLIST.md` — marked Dark/Light theme done (was already in events portal; added to inventory + history); marked Grafana alert done; marked role-based access done

---

## Session 18 — 2026-04-15

### Events portal — server-side text search
- [x] `netwatchm_server.py` — `_query_events_paged()` gains `search` param; SQLite LIKE on alert_type, src_ip, dst_ip, description
- [x] `netwatchm_server.py` — `/api/events?offset=…&q=…` passes search term server-side
- [x] `netwatchm_server.py` — search box debounced 350ms → resets page to 0 → calls `loadEvents()`; `applyFilters()` simplified to render-only (no more client-side text filter)
- [x] `netwatchm_server.py` — CSV export uses server-filtered paged result (respects `q` param)

### Documentation
- [x] `CHECKLIST.md` — marked alert suppression + events retention as already done (checklist was stale); marked events paging done after server-side search fix

---

## Session 17 — 2026-04-15

### AI Chat — alert policy context
- [x] `netwatchm_server.py` — `_build_policy_context()`: new helper that reads `suppressed.json` (currently silenced alert types) and `netwatchm.yaml` (global IP whitelist + per-type detector whitelist); appended to both `_build_device_context()` and `_build_network_context()`
- [x] `netwatchm_server.py` — `_AI_SYSTEM_PROMPT` updated to explain the Alert Policy section: whitelisted IPs never generate alerts (intentional), suppressed alert types silenced across all devices (flag if high-risk type like BRUTE_FORCE is suppressed)

### AI Chat — voice input
- [x] `ai.html` — mic button (🎤) next to Send; uses `MediaRecorder` API to capture audio locally, sends to `/api/ai/transcribe` (OpenAI Whisper); works in Brave, Firefox, Chrome, Edge — no Google Speech dependency; pulsing red indicator + status strip while recording; auto-stops at 30s; fills textarea on transcription; shows inline errors for mic permission denied or transcription failure
- [x] `netwatchm_server.py` — `POST /api/ai/transcribe`: accepts raw audio (webm/ogg/wav), sends to OpenAI Whisper (`whisper-1`), returns `{"text":"..."}`; reuses `OPENAI_API_KEY` env var

### MAC OUI vendor database
- [x] `scripts/update-oui-db.sh` — downloads IEEE MA-L OUI registry (38k+ entries), parses CSV, writes `/var/lib/netwatchm/oui.json`; sets ownership for `netwatchm` user; run once after install then periodically
- [x] `src/netwatchm/inventory/oui_lookup.py` — `lookup(mac) -> str | None`; lazy-loads `oui.json` into memory on first call; accepts any MAC format (colon/dash/dot separated)
- [x] `src/netwatchm/inventory/arp_scanner.py` — OUI lookup used as fallback vendor when arp-scan returns no vendor string
- [x] `netwatchm_server.py` — `_build_device_context()` enriches vendor via OUI lookup when inventory has no vendor; `_build_policy_context()` lists unidentified devices (no hostname + no vendor) as highest-priority unknowns; system prompt updated

### Documentation
- [x] `README.md` — updated: MAC vendor database section, service hardening section, AI context sources table, new scripts listed, project structure updated
- [x] `CLAUDE.md` — added `README.md auto-update` workflow rule: README must be updated alongside any feature change and tracked in CHECKLIST.md Documentation entry

---

## Session 16 — 2026-04-14

### Service hardening — dedicated system user
- [x] `scripts/harden-service-user.sh` — switches `netwatchm-web` from `User=root` to a dedicated `netwatchm` system user; chowns `/var/lib/netwatchm`, `/var/log/netwatchm`, `/etc/netwatchm`; secures OpenAI API key drop-in to chmod 600; idempotent and safe to re-run. Main monitor (packet capture) stays root — tshark requires CAP_NET_RAW.
- [x] `scripts/deploy-server.sh` — updated to create/install a system venv at `/usr/local/lib/netwatchm/venv` (independent of home dir); wrapper now points at system venv Python so `netwatchm` user can execute without home directory access

### Human-readable alert notifications
- [x] `src/netwatchm/alerts/alert_labels.py` — new module: `ALERT_TITLES` + `ALERT_SUMMARIES` maps for all 8 alert types; `get_title()` / `get_summary()` helpers
- [x] `src/netwatchm/alerts/email_alert.py` — subject now uses plain-English title (e.g. "Network scan detected"); body includes one-sentence summary row + cleaner table layout
- [x] `src/netwatchm/alerts/ntfy_alert.py` — `X-Title` header uses plain-English title; body prepends plain-English summary before technical detail
- [x] `tests/test_ntfy_alert.py` — updated `test_request_title_header` assertion to match new title format

---

## Session 15 — 2026-04-06

### AI Chat Integration (Web UI)
- [x] `netwatchm_server.py` — `_AI_SYSTEM_PROMPT` explains ports_observed semantics (destination ports contacted, not local listeners); ephemeral port range 32768–60999 explicitly excluded from analysis
- [x] `netwatchm_server.py` — `_PORT_NAMES` dict (40+ named services), `_EPHEMERAL_PORT_MIN = 32768`, `_fmt_bytes()` helper
- [x] `netwatchm_server.py` — `_build_device_context(ip)` reads inventory.json + events.db + flows.db; filters to known named ports only (eliminates misleading "56k open ports" reports)
- [x] `netwatchm_server.py` — `_build_network_context()` builds network-wide summary (device count, named service distribution)
- [x] `netwatchm_server.py` — `_ai_sessions: dict[str, list[dict]]` + `_ai_lock` for multi-turn conversation state; trimmed to last 20 messages per session
- [x] `netwatchm_server.py` — `_ai_ask(query, focus_ip, session_id)` calls OpenAI `gpt-4o-mini` with session history
- [x] `netwatchm_server.py` — `POST /api/ai` + `POST /api/ai/reset` routes in `do_POST`; `GET /ai.html` file serve in `do_GET`
- [x] `ai.html` — dark-theme chat UI (matching NetWatchM color scheme); device dropdown via `/api/aliases` + inventory; multi-turn session; simple markdown rendering (bold, code, lists); suggestion buttons that change by context
- [x] `openai>=1.0` added to `pyproject.toml` dependencies; `uv.lock` updated
- [x] `scripts/setup-ai-key.sh` — writes `OPENAI_API_KEY` to systemd drop-in `/etc/systemd/system/netwatchm-web.service.d/ai-env.conf`; uses `uv add openai` in project dir
- [x] `scripts/deploy-ai.sh` — copies `ai.html` to `/var/lib/netwatchm/ai.html` and restarts `netwatchm-web`
- [x] `scripts/hotdeploy.sh` — updated to also copy `ai.html` to `/var/lib/netwatchm/ai.html` (3-step deploy)

### mDNS Hostname (`netwatch.local`)
- [x] `scripts/setup-hostname.sh` — creates Avahi service XML + `netwatch-mdns.service` systemd unit; publishes `netwatch.local` → LAN IP via `avahi-publish -a -R`
- [x] Verified: `avahi-resolve -n netwatch.local` → `192.168.1.180`; all pages accessible from any LAN device by hostname

### AI Chat Nav Link — All Pages
- [x] `netwatchm_server.py` — AI Chat link added to dynamically rendered nav bars: events.html topbar, inventory.html nav, history.html nav, pcap.html nav
- [x] `src/netwatchm/reports/analytics_report.py` — full nav bar added: Connection Report, Inventory, Events, History, 🤖 AI Chat
- [x] `src/netwatchm/reports/connection_report.py` — AI Chat button added to toolbar
- [x] `netwatchm_server.py` — reports index (`/reports`) updated with AI Chat link
- [x] `netwatchm_server.py` — startup log updated to show `netwatch.local:8765` and AI Assistant URL
- [x] `scripts/patch-static-nav.sh` — Python-based patch injects AI Chat nav link into existing on-disk `analytics.html` (for pages already generated before this session)

### Bug Fixes
- [x] Fixed routing bug: `/api/ai` and `/api/ai/reset` routes were accidentally placed inside `do_DELETE` instead of `do_POST`; moved to correct location
- [x] Port analysis: AI no longer reports ephemeral outbound ports as "open ports"; context limited to named services only

### Deploy commands (session 15)
```bash
bash scripts/setup-ai-key.sh             # one-time: write OPENAI_API_KEY to systemd drop-in
bash scripts/setup-hostname.sh           # one-time: enable netwatch.local mDNS hostname
bash scripts/hotdeploy.sh               # deploy server + ai.html
bash scripts/patch-static-nav.sh        # patch existing static analytics.html with AI nav link
```

---

## Session 14 — 2026-03-29

### LAN IP / FQDN — remote access fixes
- [x] `netwatchm_server.py` — added `_get_local_ip()` helper; startup log now prints `Access via IP: https://<LAN-IP>:8765` and `Access via hostname: https://<fqdn>:8765`
- [x] `socket` added to top-level imports
- [x] `src/netwatchm/reports/connection_report.py` — Dashboard/Inventory Dashboard links now use `location.hostname` dynamically; NetWatchM Home uses relative `/`
- [x] `src/netwatchm/reports/deep_inspect.py` — Grafana Dashboard link now uses `location.hostname` dynamically
- [x] `scripts/import-dashboard.sh` — auto-detects server LAN IP and substitutes `localhost:8765` → `<LAN-IP>:8765` in Grafana panel links at import time (uses `NETWATCHM_SERVER_IP` override or UDP probe)

---

## Session 13 — 2026-03-22

### Hostname (mDNS) Access
- [x] TLS cert SAN extended to include `DNS:ai-rnd-01.local` + `DNS:ai-rnd-01` — portal now accessible via `https://ai-rnd-01.local:8765` from any LAN device
- [x] `scripts/enable-remote-access.sh` — auto-detects hostname via `hostname` and adds it to SAN
- [x] `netwatchm_server.py` `_ensure_cert()` — also includes hostname SANs on first-run cert generation
- [x] `apply-config-fix.sh` applied — adult domain alerts fixed (user machine removed from whitelist)

---

## Session 12 — 2026-03-20

- [x] Added `TrackerDomainDetector` — new `TRACKER_DOMAIN` (LOW) alert type for ads/tracking/analytics domains
  - Uses Steven Black unified adware+malware hosts list (separate from porn-only list)
  - Keeps `ADULT_DOMAIN` (MEDIUM) purely for adult content — no more false positives like `api.segment.io`
  - `TrackerDomainConfig` added to `config.py` + `load_config()`
  - `detector/tracker_domain.py`, wired into `detector/__init__.py` and `__main__.py`
  - `netwatchm.yaml.example` updated with `tracker_domain` thresholds + `TRACKER_DOMAIN` in detector_whitelist comment
  - 10 new tests — 174 total, all passing

### Deploy
```bash
bash scripts/hotdeploy.sh
```

---

## Completed
- [x] Core capture engine (tshark + async)
- [x] Threat scorer + detectors (port scan, brute force, exfiltration, new IP)
- [x] Whitelist checker (plain IPs + CIDR)
- [x] Alert handlers (terminal, logfile, sound, email)
- [x] Device inventory (store, resolver, exporter)
- [x] Terminal UI dashboard + inventory view
- [x] Systemd service (Linux) + Windows service stub
- [x] Connection report (HTML, CSV, table) — flows, protocols, domain/SNI
- [x] Investigate button in HTML report (modal + CLI command builder + context panel)
- [x] HTTPS on web server (mkcert for trusted cert; openssl self-signed fallback)
- [x] Metasploit investigate subcommand (`netwatchm investigate --target <ip>`)
- [x] arp-scan integration (cap_net_raw, no sudo needed)
- [x] Grafana Infinity dashboard
- [x] install.sh + install.bat (HTTPS cert setup via mkcert or openssl fallback)
- [x] 163 tests, all passing

## Phase 1 — Deep Inspection + GeoIP  ✅ COMPLETE (2026-02-24)
- [x] `src/netwatchm/reports/deep_inspect.py` — inspection engine (GeoIP, port scan, SSH, SMB, HTTP, RDP)
- [x] `src/netwatchm/reports/investigate_report.py` — Metasploit/nmap investigation engine
- [x] `netwatchm deep-inspect` CLI subcommand wired in `__main__.py`
- [x] `--db-path` argument added to `deep-inspect` subcommand (no hardcoded path required)
- [x] `NETWATCHM_GEOIP_DB` env var added to `netwatchm_server.py`; server passes `--db-path` to subprocess
- [x] `netwatchm-web.service` updated: sets `NETWATCHM_GEOIP_DB=/var/lib/netwatchm/GeoLite2-City.mmdb`
- [x] `install.sh` updated: auto-copies `.mmdb` from `geolite2-city-gzip/` to `/var/lib/netwatchm/` on install
- [x] GeoIP `registered_country` fallback added (fixes IPs like 1.1.1.1 returning "Unknown")
- [x] GeoLite2-City.mmdb downloaded and extracted → `geolite2-city-gzip/GeoLite2-City.mmdb` (61 MB)
- [x] `geoip2`, `paramiko`, `impacket` confirmed installed and working (via `uv sync`)
- [x] Deep Inspect buttons wired in connection report portal (Source + Destination)
- [x] `/api/deep-inspect` POST endpoint + `/api/deep-inspect/status` polling in server
- [x] End-to-end test passed: 8.8.8.8 → United States, 1.1.1.1 → Australia, risk badge, ports table, findings

### Production deploy command (run once after session)
```bash
sudo cp geolite2-city-gzip/GeoLite2-City.mmdb /var/lib/netwatchm/GeoLite2-City.mmdb
bash scripts/hotdeploy.sh   # copies netwatchm_server.py to /usr/local/lib/netwatchm/ + restart
```

---

## Phase 2 — Flow Data Store + Analytics  ✅ COMPLETE (2026-02-26)
- [x] `src/netwatchm/reports/flow_store.py` — SQLite store, 72h rolling purge, indexes on captured_at/src_ip/dst_ip
- [x] `src/netwatchm/reports/analytics_report.py` — dark-theme HTML with Chart.js (device bar, destination bar, protocol doughnut, hourly activity, per-device drill-down)
- [x] `netwatchm analytics` CLI subcommand (`--output`, `--db-path`) wired in `__main__.py`
- [x] `_report_subcommand` persists flows to SQLite after every capture (best-effort, never blocks rendering)
- [x] `netwatchm_server.py` — `FLOW_DB` env var, `_run_analytics()` runner, `/api/analytics` POST, `/api/analytics/status` GET
- [x] `netwatchm-web.service` updated: sets `NETWATCHM_FLOW_DB=/var/lib/netwatchm/flows.db`
- [x] `connection_report.py` — "📊 Analytics" button in toolbar; polls `/api/analytics`, opens result in new tab
- [x] End-to-end test passed: synthetic flows inserted → analytics HTML generated (53 MB total, 4 devices, 7 destinations, 3 protocols)

### Production deploy command (run once after session)
```bash
bash scripts/hotdeploy.sh   # copies netwatchm_server.py to /usr/local/lib/netwatchm/ + restart
```

## Phase 3 — Behavioral Threat Detectors  ✅ COMPLETE (2026-03-02)
- [x] Tor exit node detector (daily list download + real-time flow check)
- [x] Adult content domain detector — DNS query + TLS SNI, Steven Black porn list (153k domains), 24h refresh, per-device dedup, `extra_domains` config, 12 tests
- [x] Data hog alert — 24h rolling byte counter per local device (sent + received), configurable threshold (default 10 GiB), HIGH alert, per-device dedup, 12 tests
- [x] `/events.html` portal — SQLite event store (72h retention), live SPA: text search + level/type filters, expandable rows, deep-inspect link, auto-refresh, CSV export, 13 tests

---

## Stack 4 — Grafana Alerting  ✅ COMPLETE (2026-03-02)
- [x] `GET /api/alerts/data-hog` (port 8766) — returns 24h DATA_HOG event count as `[{value, time}]`
- [x] `GET /api/inventory/high` already returns `[{value, time}]` — reused for High Threat rule
- [x] `scripts/setup-grafana-alerts.sh` — interactive setup: SMTP drop-in, contact point, two alert rules
- [x] SMTP via systemd drop-in `/etc/systemd/system/grafana-server.service.d/netwatchm-smtp.conf` (no grafana.ini edits needed)
- [x] Grafana email contact point → jbaez120@gmail.com
- [x] Alert rule: **High Threat Detected** — HIGH device count > 0, fires after 1 min
- [x] Alert rule: **Data Hog Alert** — DATA_HOG events last 24h > 0, fires after 1 min
- [x] Notification policy updated: NetWatchM Email as default receiver, 4h repeat interval

### Deploy commands (run once)
```bash
bash scripts/deploy-server.sh          # deploy server with new /api/alerts/data-hog endpoint
bash scripts/setup-grafana-alerts.sh   # interactive: enter Gmail app password → wires everything
```

---

## Stack 5 — Device Friendly Names  ✅ COMPLETE (2026-03-02)
- [x] `/var/lib/netwatchm/aliases.json` — `{ip: label}` store, separate from inventory.json
- [x] `GET /api/aliases` — returns full alias dict (HTTPS server)
- [x] `POST /api/aliases` — `{ip, label}` — set or clear label (empty = delete)
- [x] `/inventory.html` — dark-theme SPA: sortable table, inline click-to-edit labels, search filter (includes label), CSV export with Label column
- [x] Grafana `/inventory.json` enriched with `label` field per device
- [x] `src/netwatchm/inventory/exporter.py` — Label as first CSV column, aliases loaded from disk
- [x] `src/netwatchm/ui/inventory_view.py` — Label column in terminal table, filter searches labels

### Access
```
https://localhost:8765/inventory.html
```

---

## Completed — Misc (pre-session 4)
- [x] Demo report script with synthetic high/medium/low risk flows (`sudo bash scripts/run-demo.sh`)
- [x] gen-report.sh uses PYTHONPATH to guarantee local source (fixes modal disappearing)
- [x] Auto-refresh the HTML report (↻ Refresh button + Auto interval + countdown, localStorage persist)
- [x] Persist connection report history (📁 History → `/reports`, last 50 kept, dark-theme index)
- [x] Alert on new/unknown devices detected by arp-scan (NEW_DEVICE MEDIUM alert → all handlers)
- [x] Grafana dashboard panels for connection report data (flows, devices, destinations, protocols, hourly)

---

## Session 4 — Windows Installer + GitHub Release  ✅ COMPLETE (2026-03-04)

### GitHub
- [x] All session 3/4 changes pushed to `al4nbr3/netwatchm` (master)
- [x] `netwachmInstall/` folder tracked in repo (was untracked)
- [x] `geolite2-city-gzip/` added to `.gitignore` (61 MB binary, not for repo)
- [x] `INSTALL.md` clone URLs fixed → `https://github.com/al4nbr3/netwatchm.git`

### Windows Installer (`netwachmInstall/install.ps1`)
- [x] **GUI progress window** — WinForms dark-theme dialog: step label, progress bar 0→100%, color-coded scrolling log
- [x] **Version detection** — reads `%PROGRAMDATA%\netwatchm\version.txt` on startup
- [x] **Upgrade / Reinstall / Uninstall / Cancel dialog** — shown when existing install detected
- [x] **Desktop shortcut** — `NetWatchM Dashboard.url` on Desktop (all users) → `https://localhost:8765/events.html`
- [x] **Start Menu shortcut** — `Start Menu\Programs\NetWatchM\NetWatchM Dashboard.url`
- [x] **Windows Defender exclusion** — auto-adds `%PROGRAMDATA%\netwatchm` on install
- [x] **Uninstall** cleans shortcuts and removes version file
- [x] **Saves version** to `version.txt` after successful install
- [x] **Error dialog** pops up if any step fails; Close button enables
- [x] **Success dialog** at end with dashboard URL confirmation
- [x] **`-Yes` flag** skips GUI entirely for CI/scripted deploys

### Documentation
- [x] `netwachmInstall/INSTALL.md` — Windows Defender/SmartScreen section added
  - Explains why popups happen (no code signing — cost not justified at this stage)
  - Step-by-step: unblock `.ps1` via Properties, bypass SmartScreen on `.exe`
  - Manual Defender exclusion command

### Deploy command (Windows — from fresh clone)
```
1. git clone https://github.com/al4nbr3/netwatchm.git
2. cd netwatchm
3. Right-click netwachmInstall\install.ps1 → Properties → Unblock → OK
4. powershell -ExecutionPolicy Bypass -File netwachmInstall\install.ps1
```

### GitHub Actions Release (v0.1.0 tag pushed)
- [x] `.github/workflows/release.yml` — builds `netwatchm-setup.exe` on Windows runner and publishes to GitHub Releases
- [x] `al4nbr3` added as publisher in exe Properties → Details tab and installer window subtitle
- [x] `installer_version.txt` — PyInstaller version metadata (CompanyName, LegalCopyright, ProductName)

### Session 5 — Windows Installer Fix + Auto Release  ✅ COMPLETE (2026-03-06)
- [x] **Root cause found**: `impacket` flagged by Windows Defender during pip install — blocked download and caused `pip install failed` error
- [x] `impacket` moved from base deps to optional `[forensics]` extra in `pyproject.toml` — Windows installer no longer installs it
- [x] SMB check in `deep_inspect.py` already catches `ImportError` gracefully — no code change needed
- [x] Pre-install Defender exclusions added for pip/uv cache + TEMP dirs in both `installer_gui.py` and `install.ps1`
- [x] **Auto version bump on every push to master** — `release.yml` now auto-increments patch version, builds exe, commits version bump, tags, and publishes GitHub Release automatically
- [x] Version bumped to `v0.2.0` across all files (`pyproject.toml`, `installer_gui.py`, `install.ps1`, `installer_version.txt`)

### Pending — Windows Installer
- [ ] Verify end-to-end install on a clean Windows machine (Desktop shortcut, services, dashboard)

---

## Session 6 — UI Polish + Network Tools  ✅ COMPLETE (2026-03-07)

---

### Session 6a — Inventory Tools + Flow History + Alert Fixes

#### Verified Devices
- [x] `/var/lib/netwatchm/verified.json` — `{ip: bool}` store, same pattern as aliases.json
- [x] `GET /api/verified` — returns full verified dict
- [x] `POST /api/verify` — `{ip, verified}` toggle
- [x] `inventory.html` — checkmark column (✓/○ toggle per device, persists immediately)

#### Per-Device nmap Scan (from inventory.html)
- [x] Scan button per row in `inventory.html` — triggers `nmap -sV --open -T4 -p 1-1024` per device
- [x] `POST /api/nmap`, `GET /api/nmap/status` — async background thread, results in modal overlay
- [x] Modal shows open ports + services on completion; no sudo required

#### Pcap Analyzer (`/pcap.html`)
- [x] Drag-and-drop pcap/pcapng upload + async background analysis via tshark
- [x] Reports: device list (MAC + OUI vendor from `/usr/share/wireshark/manuf`), DNS resolution latency (matched by client_ip + dns.id pair), TLS handshake latency (matched by tcp.stream)
- [x] `GET /api/pcap/status`, `POST /api/pcap/upload` endpoints
- [x] "📊 Pcap" nav link added to `inventory.html`
- [x] `scripts/capture-targetip.sh` — interactive: prompts for target IP, save path, duration (seconds), interface; pre-creates output file with `touch + chmod 644` to avoid tshark permission denied error
  - Renamed from `capture-switch.sh`
- [x] Nintendo Switch investigation: `scannIp.pcapng` identified `192.168.1.217` as Nintendo Co.,Ltd (MAC `98:e2:55:d4:be:85`); port scan showed all RST (no open ports), no DNS/TLS because Switch was passive during scan

#### Flow History (`/history.html`)
- [x] `flow-history.db` (SQLite) — `active_snapshot` + `flow_history` tables
- [x] `_update_flow_history()` — on each report generate: compares current flows.db snapshot vs previous active_snapshot; inactive flows written to `flow_history`; 30-day rolling purge (unpinned only)
- [x] Pin-to-keep: `pinned=1` excludes entry from automatic purge
- [x] `GET /api/flow-history`, `POST /api/flow-history/pin`, `DELETE /api/flow-history/{id}`
- [x] SPA: search bar, pin/unpin toggle, delete, date shown for each inactive connection
- [x] When Generate button is clicked: only active connections shown in report; inactive ones logged to history

#### Connection Report Toolbar Updates (`connection_report.py`)
- [x] "📱 Inventory" button → `/inventory.html`
- [x] "⏱ History" button → `/history.html`
- [x] External links group (purple): Dashboard → `http://localhost:3000`, Inventory Dashboard → `/d/netwatchm-inventory/`, NetWatchM Home → `https://localhost:8765/`
- [x] Shared new-tab toggle checkbox for the three external links, `localStorage` persists preference
- [x] `scripts/patch-report-dashboard-btn.sh` — one-time script to apply buttons to existing live `connection-report.html` (writes to `/tmp/`, then `sudo cp`)

#### Adult Domain Alert Fix
- [x] **Root cause 1:** `192.168.1.180` (user's own machine) was in the whitelist — whitelist suppresses ALL alerts from that src_ip, including ADULT_DOMAIN when browsing from that machine
- [x] **Root cause 2:** `interface: auto` in config (though enp6s0 was being selected anyway)
- [x] Fix: remove `192.168.1.180` from whitelist; set `interface: enp6s0` explicitly; add explicit `adult_domain` config block
- [x] `scripts/apply-config-fix.sh` — backs up `/etc/netwatchm/netwatchm.yaml`, applies `/tmp/netwatchm-fixed.yaml`, restarts `netwatchm` service
- [x] `/tmp/netwatchm-fixed.yaml` — corrected config (Twingate relays whitelisted, user's own IP removed)

#### Scripts Added
- [x] `scripts/hotdeploy.sh` — fast deploy: `sudo cp netwatchm_server.py /usr/local/lib/netwatchm/` + `sudo systemctl restart netwatchm-web` (two commands, no interactive prompts)
- [x] `scripts/apply-config-fix.sh` — safe config update with backup
- [x] `scripts/capture-targetip.sh` — interactive tshark capture with all params prompted

---

### Session 6b — Nav Buttons + Grafana Panel Debug

#### Navigation Buttons Added
- [x] `events.html` topbar: added "Inventory" → `/inventory.html` and "📊 Dashboard" → `http://localhost:3000/d/netwatchm-inventory/` (new tab)
- [x] `deep-inspect-{ip}.html`: navbar injected at top of every generated report — "← Inventory" → `/inventory.html`, "⚠ Events" → `/events.html?q={ip}` (pre-filtered to that device), "📊 Dashboard" → Grafana (new tab)
- [x] Changes in `netwatchm_server.py` (events.html) and `src/netwatchm/reports/deep_inspect.py`

#### Grafana Panel Investigation + Fix
- [x] Confirmed all flow endpoints return valid data via direct curl tests:
  - `/api/flows/devices/enriched` → Top Traffic Devices — Live ✅
  - `/api/flows/devices` → Top Devices by Data Sent ✅
  - `/api/flows/destinations` → Top Destinations ✅
  - `/api/flows/top-apps` → Application Activity ✅
  - `/api/flows/browsing` → Browsing Activity ✅
- [x] Root cause for "Top Devices by Data Sent" + "Top Destinations" not visible: both panels are **inside the collapsed "Connection Report" row** — click the row header in Grafana to expand

### Deploy
```bash
bash scripts/hotdeploy.sh              # deploy netwatchm_server.py → live server (port 8765/8766)
bash scripts/apply-config-fix.sh       # fix adult domain alerts (remove 192.168.1.180 from whitelist)
```

---

## Session 7 — IP Lookup Modal + Per-Detector Whitelist  ✅ COMPLETE (2026-03-07)

### Per-Detector IP Whitelist (`detector_whitelist` config)
- [x] `config.py` — `DetectorWhitelistConfig` dataclass with `is_suppressed(alert_type, ip)` method
- [x] `__main__.py` — check in `alert_dispatch_loop()` after global whitelist, before scorer/handlers
- [x] `netwatchm.yaml.example` — documented with all 7 alert types
- [x] Allows suppressing e.g. `PORT_SCAN` from one IP without silencing all alerts from that device

### IP Lookup Modal in `events.html`
- [x] Globe button on each expanded event row opens a 4-tab modal
- [x] **GeoIP tab** — country, city, region, coords, timezone, org/ISP (via GeoLite2)
- [x] **DNS tab** — reverse PTR + forward A record (`dig +short`)
- [x] **Security tab** — Tor exit check, threat level, alert history breakdown from `events.db`
- [x] **WHOIS tab** — parsed key fields + raw output
- [x] Backend: `_ip_lookup()` in `netwatchm_server.py` aggregates GeoLite2 + ipinfo.io + whois + local DB
- [x] 163 tests still passing

### Workflow Preference Added
- [x] Read `CHECKLIST.md` at the start of every session and update it with all tasks requested

---

## Session 8 — Remote Access + URL Fix  ✅ COMPLETE (2026-03-08)

### Grafana Remote Access
- [x] `scripts/configure-grafana-remote.sh` — patches `/etc/grafana/grafana.ini`: sets `domain = 192.168.1.180` + `root_url = http://192.168.1.180:3000/`; opens ufw port 3000; restarts grafana-server
- [x] Verified: Grafana accessible from remote machine at `http://192.168.1.180:3000`

### NetWatchM Portal Remote Access (`https://192.168.1.180:8765`)
- [x] TLS cert regenerated with `subjectAltName` (DNS:localhost, IP:127.0.0.1, IP:\<LAN IP\>) — old cert had `CN=localhost` only, breaking remote browser connections
- [x] `_ensure_cert()` in `netwatchm_server.py` now auto-detects LAN IP and embeds it in SAN; override with `NETWATCHM_SERVER_IP` env var
- [x] `scripts/enable-remote-access.sh` — opens ufw port 8765, regenerates cert with LAN IP SAN, restarts `netwatchm-web`
- [x] Grafana nav link (`📊 Dashboard`) changed from hardcoded `http://localhost:3000/...` to `javascript: window.open('http://'+location.hostname+':3000/...')` — works from any host
- [x] Verified: portal accessible from remote machine at `https://192.168.1.180:8765`

### Events Portal URL Fix
- [x] `events.html` pre-fill now handles `?q=` param (alongside `?ip=` and `?search=`) — deep-inspect "View Events" links use `?q={ip}`
- [x] Deployed via `bash scripts/hotdeploy.sh`

### Windows Cert Trust (remote machine)
- [x] `GET /cert` endpoint — serves `server.crt` as a downloadable file (`application/x-x509-ca-cert`)
- [x] `scripts/install-cert-windows.ps1` — clean single-command-per-line script; downloads cert from `/cert` and installs into Windows Trusted Root; run as Administrator on Windows machine
- [x] Quick bypass alternative: type `thisisunsafe` on Chrome/Edge cert error page

### Connection Report Toolbar Layout
- [x] Purple external buttons (Dashboard, Inventory Dashboard, NetWatchM) moved to second row below blue buttons
- [x] Toolbar restructured into two `.toolbar-row` divs; CSS changed to `flex-direction: column`
- [x] Purple row centered-right under Analytics using `.ext-row` class (`justify-content:center; padding-left:200px`)

### Whitelist Update
- [x] `192.168.1.248` added to global whitelist in `/etc/netwatchm/netwatchm.yaml`; service restarted

### Deploy commands (session 8)
```bash
bash scripts/hotdeploy.sh               # deploy events.html ?q= fix + cert SAN change + /cert endpoint
bash scripts/enable-remote-access.sh    # open port 8765, regen TLS cert, restart web
bash scripts/configure-grafana-remote.sh  # patch grafana.ini, open port 3000, restart grafana
```

**Windows cert install (run on Windows machine as Administrator):**
```powershell
powershell -ExecutionPolicy Bypass -File \\192.168.1.180\...\install-cert-windows.ps1
# or download the script and run it locally
```

---

## Session 9 — Linux Cert Trust (2026-03-09)

### Linux Certificate Install Script
- [x] `scripts/install-cert-linux.sh` — downloads cert from `/cert` endpoint, installs into system trusted roots (`update-ca-certificates`) and Chrome NSS store (`certutil`); accepts optional `SERVER_IP` and `PORT` args

---

## Session 10 — Security Hardening (2026-03-10)

### Hardcoded Credential Removal
- [x] `scripts/reset-grafana-password.sh` — removed hardcoded plaintext password; now prompts interactively at runtime (`read -rsp`, silent input)

---

## Session 11 — Network Diagnostics Tools (2026-03-12)

### Network Diagnostic Tools Added
- [x] Installed `conntrack` and `iperf3` packages
- [x] API endpoints added to `netwatchm_server.py`:
  - `/api/diagnostics/conntrack` — show active TCP connections
  - `/api/diagnostics/tcpstates` — show TCP connection states via `ss`
  - `/api/diagnostics/iperf` — run iperf3 bandwidth test to target IP
  - `/api/diagnostics/bandwidth/{ip}` — get bandwidth stats per device from flow DB
- [x] `deep-inspect-web.html` updated with new tabs:
  - **Network Diagnostics** — buttons for conntrack, tcpstates, iperf
  - **Bandwidth** — check per-device bandwidth from flow data

### Conntrack IP Filter Update (2026-03-12)
- [x] `/api/diagnostics/conntrack` now accepts optional `target` query param to filter by IP
- [x] `deep-inspect-web.html`: conntrack now requires target IP input; shows blank when idle

### IP Investigation Guide (2026-03-12)
- [x] Created `docs/ip-investigation-qrcards.md` — comprehensive reference for investigating suspicious IPs
- [x] Updated Quick Reference Card with tcpdump port 80/443 command
- [x] Created `docs/ip-investigation-log.md` — real investigation example with step-by-step log

### Deploy commands
```bash
bash scripts/hotdeploy.sh              # deploy netwatchm_server.py
bash scripts/copy-deep-inspect-web.sh  # copy updated HTML UI
```

---

## Pending — Next Session

### Must Do (sudo required — run manually)
- [x] **`bash scripts/apply-config-fix.sh`** — fixes adult domain alerts (removes user machine from whitelist) — applied 2026-03-22
- [ ] **Windows install test** — verify end-to-end on a clean Windows machine (overdue since session 4)

### Completed This Session (session 7)
- [x] GitHub repo moved from **public → private** (`al4nbr3/netwatchm`)
- [x] Grafana credentials removed from CHECKLIST.md (were exposed in public repo)
- [x] Test count corrected: 143 → 163
- [x] Duplicate Session 6c removed from CHECKLIST
- [x] Deploy path corrected (Phase 1/2 commands pointed to wrong binary location)
- [x] Orphaned "In Progress" section given proper label
- [x] `netwatchm.yaml.production` saved to repo root (no longer lost on reboot)
- [x] `apply-config-fix.sh` updated to read from repo file instead of `/tmp/`
- [x] `netwatchm.yaml.production` added to `.gitignore` (contains private IPs)

### Improvements / Nice to Have
- [x] **README.md** — rewritten session 15 (2026-04-06): current feature set, all portal pages, AI assistant, architecture, scripts, 174 tests
- [x] **Events retention setting** — already configurable: `alerts.event_store.retention_hours` in `netwatchm.yaml` (default 72); wired in `config.py` + `__main__.py` — checklist was stale
- [x] **Grafana alert rules** — `/api/alerts/exfiltration` endpoint added (session 19); `setup-grafana-alerts.sh` already has the rule definition
- [x] **Events portal paging** — pagination already implemented; session 18 fix: text search now server-side (`q` param in `_query_events_paged` + SQLite LIKE); search box debounced 350ms → reloads from server; CSV export uses server-filtered results
- [x] **Dark/Light theme** — added to inventory + history pages (session 19); events portal already had it; theme persists via localStorage across all pages
- [x] **Alert suppression** — already implemented: 🔒 Suppress button in every alert detail row + suppress panel in events portal header — checklist was stale
- [x] **Role-based access** — `GET /api/auth/whoami` + login modal + role badge + admin-only button visibility (session 19)
- [ ] **Mobile-friendly** — events portal not tested on phone browser (ntfy app covers this partially)
- [ ] **Code signing** — skipped (cert costs ~$300-500/yr); revisit if project grows
- [ ] **SQLite schema migrations** — 3 databases (events, flows, flow-history) have no migration system

## Grafana Setup — ✅ COMPLETE (2026-03-02)

### What works:
- Grafana 12.4.0 + Infinity v3.7.2 installed and running
- NetWatchM HTTP server on port 8766 (Grafana-only, no TLS)
- Infinity datasource "NetWatchM" configured — allowed hosts: `http://127.0.0.1:8766` AND `http://localhost:8766`
- All API endpoints confirmed working:
  - `/api/inventory/{total|high|medium|low|stats}` — device counts
  - `/api/flows/{stats|devices|destinations|protocols|hourly}` — flow data
  - `/api/flows/browsing` — local device → site activity
  - `/api/events/adult-domains` — ADULT_DOMAIN events grouped by src_ip + domain
- Dashboard imported via `scripts/import-dashboard.sh`
- Grafana credentials: stored locally — do NOT commit to repo
- `scripts/seed-events.sh` — seed live events.db with 6 synthetic test alerts

### Dashboard panels (v5):
- Stat panels: Total Devices, HIGH/MEDIUM/LOW Threat counts
- Threat Distribution donut: HIGH/MEDIUM/LOW device counts (from `/api/inventory/stats`)
- Device Inventory table: IP, Hostname, MAC, Vendor, Threat (colour-coded), Sent, Received, Last Seen
- Flow stats: Total Flows, Total Data, Active Devices (72h)
- Top Devices table: IP + host + bytes, clickable IP links → events portal + deep inspect
- Top Destinations table: IP + domain + port + bytes, clickable IP links
- Protocol Doughnut + Hourly Activity bar
- **Intelligence row:**
  - Trigger Sites: ADULT_DOMAIN events (src_ip, domain, count, last_seen)
  - Browsing Activity: local device → website (src_ip, device, site, port, bytes)

### Key lessons (jsonata vs backend parser):
- `jsonata` parser ignores column definitions — dumps all JSON fields; causes byte fields to inflate pie/bar charts
- `backend` parser respects explicit column list — use this for all panels
- All Infinity targets require `url_options: {"method": "GET", "data": ""}` or JS crashes silently
- Stat panels need `timestamp_epoch_ms` column + `filterFieldsByName` transformation to hide time field
- Specific routes (`/api/flows/browsing`) must be checked BEFORE generic `startswith` routes

### Deploy commands:
```bash
bash scripts/deploy-server.sh     # copy server + restart service
bash scripts/import-dashboard.sh  # re-import dashboard after JSON changes
```

---

---

## Session 3 — Push Notifications + Dashboard Overhaul  ✅ COMPLETE (2026-03-03)

### Stack 6 — ntfy.sh Push Notifications
- [x] `src/netwatchm/alerts/ntfy_alert.py` — NtfyAlert handler (urllib, priority map, cooldown, Bearer token)
- [x] `src/netwatchm/config.py` — NtfyAlertConfig dataclass; wired into AlertsConfig + load_config()
- [x] `src/netwatchm/__main__.py` — NtfyAlert registered when `config.alerts.ntfy.enabled`
- [x] `netwatchm.yaml.example` — ntfy section (server, topic, min_level, cooldown_seconds)
- [x] Live config `/etc/netwatchm/netwatchm.yaml` — enabled with topic `netwatchm-abc123`
- [x] `tests/test_ntfy_alert.py` — 20 tests (priority, min_level, cooldown, headers, token, URLError)
- [x] Events portal — **Test Notify** button fires live ntfy push via `POST /api/test-ntfy`

### Stack 6b — Grafana → ntfy Webhook Bridge
- [x] `POST /api/grafana-ntfy` (port 8766) — receives Grafana unified alerting webhook, forwards to ntfy
- [x] ASCII-safe header encoding (em-dash fix for latin-1 codec error)
- [x] `scripts/setup-grafana-ntfy.sh` — creates Grafana contact point + notification policy route
- [x] End-to-end tested: Grafana alert → webhook → ntfy push on phone

### GeoIP + Deploy Fix
- [x] `scripts/deploy-geoip.sh` — copies GeoLite2-City.mmdb to `/var/lib/netwatchm/`
- [x] `scripts/deploy-server.sh` — fixed to use venv Python (system python3 was missing geoip2)
  - Server now runs via bash wrapper at `/usr/local/bin/netwatchm-server` → venv Python
  - Also syncs `~/.local/bin/netwatchm` CLI from venv on deploy
- [x] GeoIP country column working in Alert History (Grafana) and deep inspect reports

### Grafana Dashboard v17 Overhaul
- [x] Color standard: HIGH=#ff9900 (orange), MEDIUM=#cc8800 (amber), LOW=#3fb950, CRITICAL=#f85149
- [x] Device Inventory panel height 14 → 8
- [x] Top Devices barchart replaced with enriched live traffic table (IP, device, sent, received, total)
  - Endpoint: `/api/flows/devices/enriched`
  - Columns have View Events + Deep Inspect data links
- [x] "Why" breakdown merged into traffic table (consolidated panel 23)
- [x] Alert History table (panel 20) — MEDIUM+ only, GeoIP country column, src_ip links to events portal
- [x] Alert History endpoint: `GET /api/events/history` (port 8766)
- [x] Application Activity donut (panel 14) replacing Protocol Mix — `/api/flows/top-apps`
- [x] Hourly Activity fixed to last 24h rolling window
- [x] Connection Report row collapsed (click to expand)
- [x] Browsing Activity deep-inspect link → `/inspect/{ip}` launcher
- [x] **Alert count stat panels** (panels 24/25/26) at y=4 filling empty space:
  - CRITICAL Alerts (red) — `/api/events/count/critical`
  - HIGH Alerts (orange) — `/api/events/count/high`
  - MEDIUM Alerts (amber) — `/api/events/count/medium`
- [x] Dashboard v17, revert tag: `dashboard-pre-cleanup`

### Deep Inspect 404 Fix
- [x] `/inspect/{ip}` launcher page — triggers POST, shows spinner, polls status, auto-redirects
- [x] Hostname injected into deep inspect report title
- [x] Events + Deep Inspect data links added to Browsing Activity and Traffic tables
- [x] `--db-path` removed from deep-inspect subprocess call (uses DEFAULT_GEOIP_DB)

### Clear Alerts + Admin Token
- [x] `DELETE /api/events` endpoint — requires `X-Admin-Token` header (env: `NETWATCHM_ADMIN_TOKEN`, default: `netwatchm-admin`)
- [x] Events portal — **🗑 Clear Alerts** button + password modal (admin token required)
- [x] `do_OPTIONS` updated: allows DELETE method + `X-Admin-Token` header

### Test Scripts
- [x] `scripts/test-all-alerts.sh` — fires all 3 channels simultaneously:
  1. Seeds events.db with MEDIUM/HIGH/CRITICAL alerts
  2. Direct ntfy pushes for all 3 levels (bypasses cooldown)
  3. POST to `/api/grafana-ntfy` to test bridge

### Deploy commands (session 3)
```bash
bash scripts/deploy-server.sh       # deploy latest server + sync CLI
bash scripts/import-dashboard.sh    # import dashboard v17 (alert count panels)
bash scripts/test-all-alerts.sh     # smoke test all alert channels
```

---

## Known Issues / Notes
- `sudo uv` fails — always use full path: `sudo /home/jbaez120/.local/bin/uv`
- Regenerate report: `sudo bash scripts/gen-report.sh` (optional duration arg, default 30s)
- Demo report (synthetic high/medium/low risk flows): `sudo bash scripts/run-demo.sh`
- Report served at https://localhost:8765/connection-report.html from /var/lib/netwatchm/
- TLS cert generated via mkcert at /var/lib/netwatchm/server.crt (browser-trusted)
- Web server service: netwatchm-web (not netwatchm-server)
- Deploy server changes: `bash scripts/deploy-server.sh`
- Live config: /etc/netwatchm/netwatchm.yaml — restart service after edits
- Email password: never in YAML, use NETWATCHM_EMAIL_PASSWORD env var
- GeoLite2-City DB: `geolite2-city-gzip/GeoLite2-City.mmdb` (local) / `/var/lib/netwatchm/GeoLite2-City.mmdb` (production)
