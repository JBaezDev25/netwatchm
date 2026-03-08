#!/usr/bin/env bash
# patch-report-dashboard-btn.sh
# Patches the live connection-report.html with the Dashboard button + new-tab toggle.
# Run once: bash scripts/patch-report-dashboard-btn.sh
# After the next report regeneration this patch is no longer needed (it's in the source).

set -euo pipefail

REPORT="/var/lib/netwatchm/connection-report.html"

if [ ! -f "$REPORT" ]; then
    echo "No report found at $REPORT — generate one first via the web UI."
    exit 1
fi

if grep -q "dash-newtab" "$REPORT"; then
    echo "Dashboard button already present — nothing to do."
    exit 0
fi

python3 - <<'PYEOF' > /tmp/patched-report.html
import sys

path = "/var/lib/netwatchm/connection-report.html"
html = open(path).read()

# ── CSS ──────────────────────────────────────────────────────────────────────
css = """
  .dash-group { display:flex; align-items:center; gap:6px; }
  #dash-btn { background:rgba(188,140,255,.15); color:#bc8cff;
    border:1px solid rgba(188,140,255,.35); border-radius:4px;
    padding:7px 14px; font-size:13px; font-weight:600; cursor:pointer;
    text-decoration:none; white-space:nowrap; }
  #dash-btn:hover { opacity:.85; }
  .toggle-wrap { display:flex; align-items:center; gap:5px;
    font-size:11px; color:var(--muted); white-space:nowrap; }
  .toggle-wrap input[type=checkbox] { appearance:none; width:30px; height:16px;
    background:var(--border); border-radius:8px; cursor:pointer;
    position:relative; transition:background .2s; }
  .toggle-wrap input[type=checkbox]:checked { background:#bc8cff; }
  .toggle-wrap input[type=checkbox]::after { content:''; position:absolute;
    width:12px; height:12px; background:#fff; border-radius:50%;
    top:2px; left:2px; transition:left .2s; }
  .toggle-wrap input[type=checkbox]:checked::after { left:16px; }"""

anchor = '#refresh-countdown { color: var(--muted); font-size: 11px; white-space: nowrap; }'
if anchor in html:
    html = html.replace(anchor, anchor + css)

# ── HTML button ──────────────────────────────────────────────────────────────
dash_html = """  <div class="dash-group">
    <a id="dash-btn" href="http://localhost:3000" onclick="return openDash(event)">&#x1F4CA; Dashboard</a>
    <label class="toggle-wrap" title="New tab or same page">
      <input type="checkbox" id="dash-newtab" onchange="saveDashPref(this.checked)">
      New tab
    </label>
  </div>"""
html = html.replace('  <button id="refresh-btn"', dash_html + '\n  <button id="refresh-btn"', 1)

# ── JS ───────────────────────────────────────────────────────────────────────
js = """
(function() {
  var chk = document.getElementById('dash-newtab');
  if (!chk) return;
  var saved = localStorage.getItem('netwatchm_dash_newtab');
  chk.checked = saved === null ? true : saved === 'true';
  updateDashTarget(chk.checked);
})();
function saveDashPref(val) {
  localStorage.setItem('netwatchm_dash_newtab', val);
  updateDashTarget(val);
}
function updateDashTarget(newTab) {
  var btn = document.getElementById('dash-btn');
  if (btn) btn.target = newTab ? '_blank' : '_self';
}
function openDash(e) {
  var newTab = document.getElementById('dash-newtab').checked;
  if (newTab) { window.open('http://localhost:3000', '_blank'); return false; }
  window.location.href = 'http://localhost:3000';
  return false;
}
"""
html = html.replace('<script>\n', '<script>\n' + js, 1)

print(html, end='')
PYEOF

sudo cp /tmp/patched-report.html "$REPORT"
echo "[OK] Dashboard button added to $REPORT"
