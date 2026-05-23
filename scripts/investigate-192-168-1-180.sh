#!/usr/bin/env bash
# Evidence-gathering script for investigating 192.168.1.180 → 142.251.163.83.
#
# Reads (root-owned):
#   /var/lib/netwatchm/events.db
#   /var/lib/netwatchm/flows.db
#   /var/lib/netwatchm/inventory.json
#   /var/lib/netwatchm/aliases.json
#   /var/log/netwatchm/netwatchm.log
#
# Writes a fresh evidence dump under /tmp/investigate-192.168.1.180/.
# Also runs `netwatchm deep-inspect` (active port scan) on 192.168.1.180.

set -euo pipefail

SRC="192.168.1.180"
DST="142.251.163.83"
EVENT_TS="2026-05-08T19:30:08"

OUT_DIR="/tmp/investigate-${SRC}"
EVENTS_DB="/var/lib/netwatchm/events.db"
FLOWS_DB="/var/lib/netwatchm/flows.db"
INVENTORY="/var/lib/netwatchm/inventory.json"
ALIASES="/var/lib/netwatchm/aliases.json"
LOG="/var/log/netwatchm/netwatchm.log"

echo "==> Investigation: ${SRC} -> ${DST}"
echo "==> Output: ${OUT_DIR}"
sudo mkdir -p "${OUT_DIR}"
sudo chmod 755 "${OUT_DIR}"

# ────────────────────────────────────────────────────────────────────────────
# 1. Events.db  — every alert touching either IP in the last 72h
# ────────────────────────────────────────────────────────────────────────────
echo
echo "[1/6] events.db — alerts involving ${SRC} or ${DST} (72h)"
sudo sqlite3 -header -column "${EVENTS_DB}" "
  SELECT
    datetime(timestamp, 'unixepoch', 'localtime') AS time,
    alert_type, level, src_ip, dst_ip,
    substr(description, 1, 90) AS description
  FROM events
  WHERE (src_ip = '${SRC}' OR dst_ip = '${SRC}'
      OR src_ip = '${DST}' OR dst_ip = '${DST}')
    AND timestamp >= strftime('%s','now') - 72*3600
  ORDER BY timestamp DESC;
" | sudo tee "${OUT_DIR}/01-events.txt" > /dev/null

echo
echo "    Counts by alert type:"
sudo sqlite3 "${EVENTS_DB}" "
  SELECT alert_type, COUNT(*) AS n
  FROM events
  WHERE (src_ip = '${SRC}' OR dst_ip = '${SRC}'
      OR src_ip = '${DST}' OR dst_ip = '${DST}')
    AND timestamp >= strftime('%s','now') - 72*3600
  GROUP BY alert_type
  ORDER BY n DESC;
" | sudo tee "${OUT_DIR}/01-events-summary.txt" | sed 's/^/      /'

# ────────────────────────────────────────────────────────────────────────────
# 2. Flows.db — all flows for the (src,dst) pair + top destinations
# ────────────────────────────────────────────────────────────────────────────
echo
echo "[2/6] flows.db — ${SRC} -> ${DST} traffic"
sudo sqlite3 -header -column "${FLOWS_DB}" "
  SELECT
    captured_at, src_host, dst_ip, dst_port, protocol,
    domain, packets, bytes,
    datetime(first_seen,'unixepoch','localtime') AS first_seen,
    datetime(last_seen, 'unixepoch','localtime') AS last_seen
  FROM flows
  WHERE src_ip='${SRC}' AND dst_ip='${DST}'
  ORDER BY last_seen DESC;
" | sudo tee "${OUT_DIR}/02-flows-pair.txt" > /dev/null

echo "    Top 20 external destinations from ${SRC}:"
sudo sqlite3 -header -column "${FLOWS_DB}" "
  SELECT dst_ip, dst_port, protocol, domain,
    SUM(packets) AS packets, SUM(bytes) AS bytes,
    COUNT(*) AS flows
  FROM flows
  WHERE src_ip='${SRC}'
  GROUP BY dst_ip, dst_port, protocol
  ORDER BY bytes DESC
  LIMIT 20;
" | sudo tee "${OUT_DIR}/02-flows-top-dst.txt" | sed 's/^/      /'

echo "    Port histogram for ${SRC}:"
sudo sqlite3 -header -column "${FLOWS_DB}" "
  SELECT dst_port, protocol, COUNT(*) AS flows, SUM(bytes) AS bytes
  FROM flows
  WHERE src_ip='${SRC}'
  GROUP BY dst_port, protocol
  ORDER BY flows DESC;
" | sudo tee "${OUT_DIR}/02-flows-ports.txt" > /dev/null

# ────────────────────────────────────────────────────────────────────────────
# 3. Inventory & alias for 192.168.1.180
# ────────────────────────────────────────────────────────────────────────────
echo
echo "[3/6] inventory.json — record for ${SRC}"
sudo python3 -c "
import json, sys
data = json.load(open('${INVENTORY}'))
rec = data.get('${SRC}') if isinstance(data, dict) else None
if rec is None and isinstance(data, list):
    rec = next((r for r in data if r.get('ip') == '${SRC}'), None)
print(json.dumps(rec, indent=2) if rec else 'NOT FOUND in inventory')
" | sudo tee "${OUT_DIR}/03-inventory.json" > /dev/null
sudo cat "${OUT_DIR}/03-inventory.json" | sed 's/^/      /'

echo
echo "    Alias / verified flag:"
if sudo test -f "${ALIASES}"; then
  sudo python3 -c "
import json
data = json.load(open('${ALIASES}'))
print('alias:', data.get('${SRC}', '(none)'))
" | sed 's/^/      /'
fi

# ────────────────────────────────────────────────────────────────────────────
# 4. Reverse DNS + WHOIS for 142.251.163.83
# ────────────────────────────────────────────────────────────────────────────
echo
echo "[4/6] DNS + WHOIS for ${DST}"
{
  echo "── dig -x ${DST} ──"
  dig -x "${DST}" +short || true
  echo
  echo "── whois ${DST} (first 40 lines) ──"
  whois "${DST}" 2>/dev/null | head -40 || echo "(whois not installed)"
} | sudo tee "${OUT_DIR}/04-dns-whois.txt" | sed 's/^/      /'

# ────────────────────────────────────────────────────────────────────────────
# 5. Log slice around event timestamp
# ────────────────────────────────────────────────────────────────────────────
echo
echo "[5/6] netwatchm.log — entries mentioning ${SRC} or ${DST}"
if sudo test -f "${LOG}"; then
  sudo grep -E "${SRC}|${DST}" "${LOG}" | tail -200 | sudo tee "${OUT_DIR}/05-log-grep.txt" > /dev/null
  echo "      Wrote $(sudo wc -l < "${OUT_DIR}/05-log-grep.txt") matching log lines"
else
  echo "      (log file not found at ${LOG})"
fi

# ────────────────────────────────────────────────────────────────────────────
# 6. Active deep-inspect of 192.168.1.180
# ────────────────────────────────────────────────────────────────────────────
echo
echo "[6/6] netwatchm deep-inspect ${SRC}  (active port scan, ~30-60s)"
DEEP_OUT="${OUT_DIR}/06-deep-inspect.html"
if command -v netwatchm > /dev/null 2>&1; then
  sudo netwatchm deep-inspect --target "${SRC}" --output "${DEEP_OUT}" || true
  echo "      Report: ${DEEP_OUT}"
elif [ -x "/usr/local/lib/netwatchm/venv/bin/netwatchm" ]; then
  sudo /usr/local/lib/netwatchm/venv/bin/netwatchm deep-inspect --target "${SRC}" --output "${DEEP_OUT}" || true
  echo "      Report: ${DEEP_OUT}"
else
  echo "      (netwatchm CLI not found — skipping deep-inspect)"
fi

# ────────────────────────────────────────────────────────────────────────────
# 7. Consolidate everything into a single shareable text file
# ────────────────────────────────────────────────────────────────────────────
BUNDLE="${OUT_DIR}/evidence-bundle.txt"
echo
echo "[7/7] Consolidating into ${BUNDLE}"

_section() {
  local title="$1" file="$2"
  echo
  echo "================================================================"
  echo "  ${title}"
  echo "================================================================"
  if sudo test -f "${file}"; then
    sudo cat "${file}"
  else
    echo "(no data — file ${file} not produced)"
  fi
}

{
  echo "NetWatchM investigation bundle"
  echo "Subject: ${SRC} -> ${DST}"
  echo "Reference event timestamp: ${EVENT_TS}"
  echo "Generated: $(date -Iseconds)"
  echo "Host: $(hostname)"

  _section "1. EVENTS — alerts touching ${SRC} or ${DST} (last 72h)"            "${OUT_DIR}/01-events.txt"
  _section "1b. EVENTS — counts by alert_type"                                  "${OUT_DIR}/01-events-summary.txt"
  _section "2. FLOWS — ${SRC} -> ${DST}"                                        "${OUT_DIR}/02-flows-pair.txt"
  _section "2b. FLOWS — top 20 destinations from ${SRC}"                        "${OUT_DIR}/02-flows-top-dst.txt"
  _section "2c. FLOWS — port histogram for ${SRC}"                              "${OUT_DIR}/02-flows-ports.txt"
  _section "3. INVENTORY — record for ${SRC}"                                   "${OUT_DIR}/03-inventory.json"
  _section "4. DNS + WHOIS — ${DST}"                                            "${OUT_DIR}/04-dns-whois.txt"
  _section "5. LOG — lines mentioning ${SRC} or ${DST} (last 200)"              "${OUT_DIR}/05-log-grep.txt"

  echo
  echo "================================================================"
  echo "  6. DEEP-INSPECT — see HTML report (not inlined)"
  echo "================================================================"
  if sudo test -f "${DEEP_OUT}"; then
    echo "HTML report: ${DEEP_OUT}"
    echo "Size: $(sudo stat -c%s "${DEEP_OUT}" 2>/dev/null || echo unknown) bytes"
  else
    echo "(no deep-inspect report produced)"
  fi
} | sudo tee "${BUNDLE}" > /dev/null

# Make bundle world-readable so the user can copy/share without sudo
sudo chmod 644 "${BUNDLE}"

echo
echo "──────────────────────────────────────────────────────────────"
echo "Done. All evidence under ${OUT_DIR}:"
sudo ls -la "${OUT_DIR}"
echo
echo "  →  Single shareable file:  ${BUNDLE}"
echo "  →  Size:                   $(sudo stat -c%s "${BUNDLE}" 2>/dev/null || echo unknown) bytes"
echo "  →  Deep-inspect HTML:      file://${DEEP_OUT}"
echo
echo "  Cat the bundle:   cat ${BUNDLE}"
echo "  Copy to clipboard (X11):  xclip -sel clip < ${BUNDLE}"
echo "  Copy to clipboard (Wayland):  wl-copy < ${BUNDLE}"
