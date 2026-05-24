"""Render the analytics portal HTML from FlowStore query data."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def _fmt_bytes(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {unit}" if unit != "B" else f"{b} B"
        b //= 1024
    return f"{b} TB"


def render_analytics_html(data: dict, output_path: str) -> None:
    """Write a standalone dark-theme analytics portal to output_path."""

    generated = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    totals = data.get("totals", {})
    devices = data.get("devices", [])
    top_dst = data.get("top_destinations", [])
    protocols = data.get("protocols", [])
    hourly = data.get("hourly", [])
    device_details = data.get("device_details", [])

    # ── Chart.js data ────────────────────────────────────────────────────────
    # Device bar chart
    dev_labels = json.dumps([d["host"] for d in devices])
    dev_bytes  = json.dumps([d["bytes"] for d in devices])

    # Top destinations horizontal bar
    dst_labels = json.dumps([d["domain"][:40] for d in top_dst])
    dst_bytes  = json.dumps([d["bytes"] for d in top_dst])

    # Protocol doughnut
    proto_labels = json.dumps([p["name"] for p in protocols])
    proto_bytes  = json.dumps([p["bytes"] for p in protocols])

    # Hourly line chart
    hourly_labels = json.dumps([h["hour"][-5:] for h in hourly])   # "HH:00"
    hourly_bytes  = json.dumps([h["bytes"] for h in hourly])

    # ── Summary stat cards ───────────────────────────────────────────────────
    stats_html = f"""
<div class="stats-row">
  <div class="stat-card">
    <div class="stat-label">Total Flows (72h)</div>
    <div class="stat-value">{totals.get('flows', 0):,}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Total Data</div>
    <div class="stat-value">{_fmt_bytes(totals.get('bytes', 0))}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Total Packets</div>
    <div class="stat-value">{totals.get('packets', 0):,}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Devices Active</div>
    <div class="stat-value">{len(devices)}</div>
  </div>
</div>"""

    # ── Device drill-down table ───────────────────────────────────────────────
    drill_sections = ""
    for entry in device_details:
        dev = entry["device"]
        flows = entry["flows"]
        if not flows:
            continue
        rows = "".join(
            f"<tr>"
            f"<td>{f['domain']}</td>"
            f"<td style='color:var(--muted)'>{f['dst']}</td>"
            f"<td>{f['proto']}</td>"
            f"<td class='num'>{_fmt_bytes(f['bytes'])}</td>"
            f"<td style='color:var(--muted);font-size:11px'>{f['last'][:16] if f['last'] else '—'}</td>"
            f"</tr>"
            for f in flows
        )
        drill_sections += f"""
<details class="drill">
  <summary>
    <span class="drill-ip">{dev['host']}</span>
    <span class="drill-sub">{dev['ip']}</span>
    <span class="drill-bytes">{_fmt_bytes(dev['bytes'])}</span>
  </summary>
  <table class="drill-table">
    <thead><tr>
      <th>Destination</th><th>IP</th><th>Protocol</th>
      <th class="num">Data</th><th>Last Seen</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</details>"""

    if not drill_sections:
        drill_sections = '<p style="color:var(--muted);font-size:13px">No flow data yet.</p>'

    # ── Full HTML ─────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatchM — Analytics</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg:#0d1117; --surface:#161b22; --border:#30363d;
    --text:#e6edf3; --muted:#8b949e; --accent:#58a6ff;
    --green:#3fb950; --yellow:#e3b341; --red:#f85149;
  }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:var(--bg); color:var(--text); font-family:monospace;
          font-size:13px; padding:24px; }}
  h1 {{ color:var(--accent); font-size:20px; margin-bottom:4px; }}
  .meta {{ color:var(--muted); font-size:12px; margin-bottom:20px; }}
  .nav {{ display:flex; gap:12px; margin-bottom:24px; }}
  .nav a {{ color:var(--accent); text-decoration:none; font-size:12px;
             border:1px solid var(--border); border-radius:4px; padding:4px 12px; }}
  .nav a:hover {{ background:var(--surface); }}
  .stats-row {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:24px; }}
  .stat-card {{ background:var(--surface); border:1px solid var(--border);
                border-radius:8px; padding:14px 20px; flex:1; min-width:140px; }}
  .stat-label {{ color:var(--muted); font-size:11px; text-transform:uppercase;
                 letter-spacing:.5px; margin-bottom:6px; }}
  .stat-value {{ color:var(--text); font-size:22px; font-weight:700; }}
  .charts-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:16px;
                  margin-bottom:24px; }}
  @media(max-width:900px) {{ .charts-grid {{ grid-template-columns:1fr; }} }}
  .chart-card {{ background:var(--surface); border:1px solid var(--border);
                 border-radius:8px; padding:16px 20px; }}
  .chart-title {{ color:var(--accent); font-size:12px; font-weight:600;
                  text-transform:uppercase; letter-spacing:.5px; margin-bottom:14px; }}
  .chart-wrap {{ position:relative; height:220px; }}
  .chart-wrap-tall {{ position:relative; height:280px; }}
  .section-title {{ color:var(--accent); font-size:13px; font-weight:600;
                    text-transform:uppercase; letter-spacing:.5px;
                    margin-bottom:14px; }}
  .drill {{ background:var(--surface); border:1px solid var(--border);
            border-radius:6px; margin-bottom:8px; overflow:hidden; }}
  .drill summary {{ display:flex; align-items:center; gap:12px; padding:10px 14px;
                    cursor:pointer; list-style:none; }}
  .drill summary::-webkit-details-marker {{ display:none; }}
  .drill summary:hover {{ background:rgba(88,166,255,.05); }}
  .drill summary::before {{ content:'›'; color:var(--muted); font-size:16px;
                             transition:transform .15s; }}
  details[open] summary::before {{ transform:rotate(90deg); }}
  .drill-ip {{ color:var(--text); font-weight:600; flex:1; }}
  .drill-sub {{ color:var(--muted); font-size:11px; }}
  .drill-bytes {{ color:var(--green); font-size:12px; }}
  .drill-table {{ width:100%; border-collapse:collapse; font-size:12px;
                  padding:0 14px 12px; }}
  .drill-table th {{ color:var(--muted); text-align:left; padding:6px 8px;
                     border-bottom:1px solid var(--border); font-size:11px; }}
  .drill-table td {{ padding:5px 8px; border-bottom:1px solid rgba(48,54,61,.5); }}
  .drill-table tr:last-child td {{ border-bottom:none; }}
  .num {{ text-align:right; }}
</style>
</head>
<body>

<h1>NetWatchM — Analytics</h1>
<div class="meta">Last updated: {generated} &nbsp;|&nbsp; Retention: 72 hours</div>

<nav class="nav">
  <a href="/connection-report.html">&#8592; Connection Report</a>
  <a href="/inventory.html">Inventory</a>
  <a href="/events.html">Events</a>
  <a href="/history.html">History</a>
  <a href="/firewall.html">&#128737; Firewall</a>
  <a href="/ai.html" style="color:#58a6ff;font-weight:bold">&#129302; AI Chat</a>
</nav>

{stats_html}

<div class="charts-grid">

  <div class="chart-card">
    <div class="chart-title">Data per Device (last 72h)</div>
    <div class="chart-wrap-tall">
      <canvas id="devChart"></canvas>
    </div>
  </div>

  <div class="chart-card">
    <div class="chart-title">Top 10 Destinations by Data</div>
    <div class="chart-wrap-tall">
      <canvas id="dstChart"></canvas>
    </div>
  </div>

  <div class="chart-card">
    <div class="chart-title">Protocol Breakdown</div>
    <div class="chart-wrap">
      <canvas id="protoChart"></canvas>
    </div>
  </div>

  <div class="chart-card">
    <div class="chart-title">Hourly Activity</div>
    <div class="chart-wrap">
      <canvas id="hourlyChart"></canvas>
    </div>
  </div>

</div>

<div class="section-title">Per-Device Drill-Down</div>
{drill_sections}

<script>
const ACCENT  = '#58a6ff';
const GREEN   = '#3fb950';
const YELLOW  = '#e3b341';
const RED     = '#f85149';
const PURPLE  = '#a371f7';
const ORANGE  = '#f0883e';
const MUTED   = '#8b949e';
const PALETTE = [ACCENT, GREEN, YELLOW, RED, PURPLE, ORANGE,
                 '#79c0ff','#56d364','#ffa657','#ff7b72'];

const OPTS_BASE = {{
  responsive: true,
  maintainAspectRatio: false,
  plugins: {{ legend: {{ display: false }} }},
  scales: {{
    x: {{ ticks: {{ color: MUTED, font: {{ size:10 }} }},
          grid:  {{ color:'rgba(48,54,61,.6)' }} }},
    y: {{ ticks: {{ color: MUTED, font: {{ size:10 }},
                   callback: v => fmtBytes(v) }},
          grid:  {{ color:'rgba(48,54,61,.6)' }} }},
  }},
}};

function fmtBytes(b) {{
  if (b === 0) return '0 B';
  const units = ['B','KB','MB','GB','TB'];
  let i = 0;
  while (b >= 1024 && i < units.length - 1) {{ b /= 1024; i++; }}
  return b.toFixed(1) + ' ' + units[i];
}}

// Device bar chart
new Chart(document.getElementById('devChart'), {{
  type: 'bar',
  data: {{
    labels: {dev_labels},
    datasets: [{{ data: {dev_bytes},
      backgroundColor: {dev_labels}.map((_,i) => PALETTE[i % PALETTE.length]),
      borderRadius: 4, borderSkipped: false }}]
  }},
  options: {{ ...OPTS_BASE,
    plugins: {{ legend: {{ display:false }},
               tooltip: {{ callbacks: {{ label: ctx => fmtBytes(ctx.raw) }} }} }},
  }},
}});

// Destinations horizontal bar chart
new Chart(document.getElementById('dstChart'), {{
  type: 'bar',
  data: {{
    labels: {dst_labels},
    datasets: [{{ data: {dst_bytes},
      backgroundColor: ACCENT + 'cc',
      borderRadius: 4, borderSkipped: false }}]
  }},
  options: {{
    ...OPTS_BASE,
    indexAxis: 'y',
    plugins: {{ legend: {{ display:false }},
               tooltip: {{ callbacks: {{ label: ctx => fmtBytes(ctx.raw) }} }} }},
    scales: {{
      x: {{ ticks: {{ color: MUTED, font:{{size:10}}, callback: v => fmtBytes(v) }},
            grid:  {{ color:'rgba(48,54,61,.6)' }} }},
      y: {{ ticks: {{ color: MUTED, font:{{size:10}} }},
            grid:  {{ display:false }} }},
    }},
  }},
}});

// Protocol doughnut
new Chart(document.getElementById('protoChart'), {{
  type: 'doughnut',
  data: {{
    labels: {proto_labels},
    datasets: [{{ data: {proto_bytes},
      backgroundColor: PALETTE,
      borderColor: '#0d1117', borderWidth: 2 }}]
  }},
  options: {{
    responsive: true,
    maintainAspectRatio: false,
    plugins: {{
      legend: {{ display:true, position:'right',
                 labels: {{ color: MUTED, font:{{size:11}}, boxWidth:12 }} }},
      tooltip: {{ callbacks: {{ label: ctx => ctx.label + ': ' + fmtBytes(ctx.raw) }} }},
    }},
  }},
}});

// Hourly line chart
new Chart(document.getElementById('hourlyChart'), {{
  type: 'bar',
  data: {{
    labels: {hourly_labels},
    datasets: [{{ data: {hourly_bytes},
      backgroundColor: GREEN + '80',
      borderColor: GREEN,
      borderWidth: 1, borderRadius: 2 }}]
  }},
  options: {{
    ...OPTS_BASE,
    plugins: {{ legend: {{ display:false }},
               tooltip: {{ callbacks: {{ label: ctx => fmtBytes(ctx.raw) }} }} }},
  }},
}});
</script>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
