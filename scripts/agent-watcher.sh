#!/usr/bin/env bash
# agent-watcher.sh
#
# Polls /var/lib/netwatchm/agent_actions.db for newly-completed agent
# decisions (rationale changes from NULL → non-NULL) and pushes a
# notification to ntfy.sh for each one.
#
# Usage:
#   bash scripts/agent-watcher.sh --once          # process current backlog and exit
#   bash scripts/agent-watcher.sh --foreground    # poll loop, logs to stdout
#   bash scripts/agent-watcher.sh --daemon        # background via nohup, logs to /tmp/agent-watcher.log
#   bash scripts/agent-watcher.sh --status        # print last-seen id + pid + log path
#   bash scripts/agent-watcher.sh --stop          # kill the background daemon
#
# State file: $STATE_FILE — stores the last id that has been notified about.
# Safe to interrupt and restart; nothing is double-notified.
set -euo pipefail

DB="${NETWATCHM_AGENT_DB:-/var/lib/netwatchm/agent_actions.db}"
NTFY_SERVER="${NTFY_SERVER:-https://ntfy.sh}"
NTFY_TOPIC="${NTFY_TOPIC:-netwatchm-abc123}"
POLL_INTERVAL="${POLL_INTERVAL:-30}"   # seconds between checks
STATE_FILE="${STATE_FILE:-/tmp/agent-watcher.last_id}"
LOG_FILE="${LOG_FILE:-/tmp/agent-watcher.log}"
PID_FILE="${PID_FILE:-/tmp/agent-watcher.pid}"

# --- helpers ---
log() { echo "$(date -Iseconds) $*"; }

read_last_id() {
  if [[ -f "$STATE_FILE" ]]; then cat "$STATE_FILE"; else echo 0; fi
}

write_last_id() {
  echo "$1" > "$STATE_FILE"
}

# Query for completed decisions (rationale populated) with id > last_seen.
# Output one row per line: id|ts|max_severity|events_seen|rationale_preview
# Rationale newlines and pipes are flattened to spaces in SQL so `while read`
# sees exactly one row per decision.
query_new() {
  local last_id="$1"
  sqlite3 -separator '|' "$DB" "
    SELECT
      id,
      datetime(ts,'unixepoch','localtime'),
      COALESCE(max_severity, ''),
      events_seen,
      substr(
        replace(replace(replace(rationale, char(10), ' '), char(13), ' '), '|', '/'),
        1, 400
      )
    FROM agent_decisions
    WHERE id > $last_id AND rationale IS NOT NULL
    ORDER BY id ASC;
  " 2>/dev/null || true
}

push_ntfy() {
  local id="$1"
  local when="$2"
  local severity="$3"
  local events_seen="$4"
  local preview="$5"

  local title="Agent decision #${id} — ${severity} (${events_seen} events)"
  local prio
  case "$severity" in
    CRITICAL) prio=5 ;;
    HIGH)     prio=4 ;;
    MEDIUM)   prio=3 ;;
    *)        prio=2 ;;
  esac
  # Truncate preview to safe header-safe length (used in body, not header)
  local body
  body=$(printf "%s\n\n%s\n%s" "$when" "$preview" "Audit row id=${id}")

  # POST to ntfy. ASCII-safe headers; body is UTF-8 fine.
  if curl -fsS \
       -H "Title: $(echo "$title" | tr -d '\r\n' | iconv -f UTF-8 -t ASCII//TRANSLIT 2>/dev/null || echo "$title")" \
       -H "Priority: $prio" \
       -H "Tags: robot" \
       -d "$body" \
       "${NTFY_SERVER}/${NTFY_TOPIC}" >/dev/null 2>&1; then
    log "pushed id=$id severity=$severity"
  else
    log "ntfy POST failed for id=$id"
    return 1
  fi
}

process_once() {
  local last_id
  last_id=$(read_last_id)
  local new_max="$last_id"

  while IFS='|' read -r id when sev events_seen preview; do
    [[ -z "$id" ]] && continue
    push_ntfy "$id" "$when" "$sev" "$events_seen" "$preview" || return 1
    new_max="$id"
  done < <(query_new "$last_id")

  if [[ "$new_max" != "$last_id" ]]; then
    write_last_id "$new_max"
  fi
}

run_loop() {
  log "agent-watcher starting (db=$DB topic=$NTFY_TOPIC interval=${POLL_INTERVAL}s)"
  log "last_id at start = $(read_last_id)"
  while true; do
    process_once || log "process_once errored — continuing"
    sleep "$POLL_INTERVAL"
  done
}

# --- modes ---
case "${1:-}" in
  --once)
    process_once
    log "done. last_id now = $(read_last_id)"
    ;;
  --foreground|"")
    run_loop
    ;;
  --daemon)
    if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      echo "Already running (pid $(cat "$PID_FILE")). Use --stop first." >&2
      exit 1
    fi
    nohup bash "$0" --foreground >> "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    echo "Started in background. pid=$(cat "$PID_FILE") log=$LOG_FILE"
    ;;
  --status)
    echo "db        : $DB"
    echo "topic     : $NTFY_TOPIC"
    echo "state     : $STATE_FILE (last_id = $(read_last_id))"
    echo "log       : $LOG_FILE"
    if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      echo "daemon    : running (pid $(cat "$PID_FILE"))"
    else
      echo "daemon    : not running"
    fi
    echo
    echo "last 8 log lines:"
    tail -n 8 "$LOG_FILE" 2>/dev/null || echo "  (no log yet)"
    ;;
  --stop)
    if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      kill "$(cat "$PID_FILE")"
      rm -f "$PID_FILE"
      echo "Stopped."
    else
      echo "Not running."
      rm -f "$PID_FILE"
    fi
    ;;
  --help|-h)
    sed -n '1,30p' "$0"
    ;;
  *)
    echo "Unknown option: $1" >&2
    echo "Try --help" >&2
    exit 1
    ;;
esac
