"""Monitor mode dashboard: Rich Live 4-panel layout."""
from __future__ import annotations

import time
from collections import deque
from datetime import datetime, timedelta

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import Alert, Packet, ThreatLevel

_MAX_TRAFFIC_ROWS = 50
_MAX_ALERT_ROWS = 50


def _level_color(level: ThreatLevel) -> str:
    return level.color


class Dashboard:
    """Rich Live 4-panel dashboard for Monitor mode.

    Panels:
    - Header bar: interface, threat level, uptime
    - Live traffic (last 50 packets)
    - Alert log (last 50 alerts)
    - Footer: top talkers, pps, alert count, help
    """

    def __init__(self, interface: str, console: Console | None = None) -> None:
        self._interface = interface
        self._console = console or Console()
        self._start_time = time.time()
        self._traffic: deque[Packet] = deque(maxlen=_MAX_TRAFFIC_ROWS)
        self._alert_log: deque[Alert] = deque(maxlen=_MAX_ALERT_ROWS)
        self._current_level = ThreatLevel.LOW
        self._pps: float = 0.0
        self._pkt_times: deque[float] = deque(maxlen=500)
        self._live: Live | None = None

    def add_packet(self, packet: Packet) -> None:
        self._traffic.append(packet)
        self._pkt_times.append(time.time())

    def add_alert(self, alert: Alert) -> None:
        self._alert_log.append(alert)

    def set_threat_level(self, level: ThreatLevel) -> None:
        self._current_level = level

    def _compute_pps(self) -> float:
        now = time.time()
        window = [t for t in self._pkt_times if now - t < 1.0]
        return float(len(window))

    def _uptime_str(self) -> str:
        elapsed = int(time.time() - self._start_time)
        return str(timedelta(seconds=elapsed))

    def _build_header(self) -> Panel:
        level = self._current_level
        color = _level_color(level)
        ts = datetime.now().strftime("%H:%M:%S")
        text = Text.assemble(
            ("NetWatchM", "bold cyan"),
            ("  |  iface: ", "dim"),
            (self._interface, "cyan"),
            ("  |  ", "dim"),
            (f"● {level.name}", color),
            ("  |  uptime: ", "dim"),
            (self._uptime_str(), ""),
            ("  |  ", "dim"),
            (ts, "dim"),
        )
        return Panel(text, style="on grey7", height=3)

    def _build_traffic_panel(self) -> Panel:
        table = Table(
            show_header=True,
            header_style="bold cyan",
            box=None,
            padding=(0, 1),
            expand=True,
        )
        table.add_column("Src IP", style="green", no_wrap=True, max_width=17)
        table.add_column("→", style="dim", width=1)
        table.add_column("Dst IP", style="yellow", no_wrap=True, max_width=17)
        table.add_column("Proto", style="cyan", width=6)
        table.add_column("Bytes", justify="right", width=7)

        for pkt in list(self._traffic)[-_MAX_TRAFFIC_ROWS:]:
            table.add_row(
                pkt.src_ip or "—",
                "→",
                pkt.dst_ip or "—",
                (pkt.protocol or "—")[:6],
                str(pkt.length),
            )
        return Panel(table, title="Live Traffic", border_style="blue")

    def _build_alert_panel(self) -> Panel:
        table = Table(
            show_header=True,
            header_style="bold red",
            box=None,
            padding=(0, 1),
            expand=True,
        )
        table.add_column("Time", width=8, style="dim")
        table.add_column("Level", width=8)
        table.add_column("Type", width=14)
        table.add_column("Description")

        for alert in list(self._alert_log)[-_MAX_ALERT_ROWS:]:
            color = _level_color(alert.level)
            table.add_row(
                alert.timestamp.strftime("%H:%M:%S"),
                f"[{color}]{alert.level.name}[/{color}]",
                alert.alert_type,
                alert.description,
            )
        return Panel(table, title="Alert Log", border_style="red")

    def _build_footer(self) -> Panel:
        pps = self._compute_pps()
        # Top talkers: top 3 src IPs by frequency
        ip_counts: dict[str, int] = {}
        for pkt in self._traffic:
            if pkt.src_ip:
                ip_counts[pkt.src_ip] = ip_counts.get(pkt.src_ip, 0) + 1
        top = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        talkers = "  ".join(f"{ip}({n})" for ip, n in top) or "—"

        text = Text.assemble(
            ("Top Talkers: ", "bold"),
            (talkers, "green"),
            ("  |  Pkts/s: ", "bold"),
            (f"{pps:.0f}", "cyan"),
            ("  |  Alerts: ", "bold"),
            (str(len(self._alert_log)), "red"),
            "\n",
            ("  [I] Inventory  ", "bold yellow"),
            ("  [Q] Quit", "bold red"),
        )
        return Panel(text, style="on grey7", height=4)

    def build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(self._build_header(), name="header", size=3),
            Layout(name="main"),
            Layout(self._build_footer(), name="footer", size=4),
        )
        layout["main"].split_row(
            Layout(self._build_traffic_panel(), name="traffic"),
            Layout(self._build_alert_panel(), name="alerts"),
        )
        return layout

    def start(self) -> Live:
        self._live = Live(
            self.build_layout(),
            console=self._console,
            refresh_per_second=2,
            screen=True,
        )
        self._live.start()
        return self._live

    def update(self) -> None:
        if self._live:
            self._live.update(self.build_layout())

    def stop(self) -> None:
        if self._live:
            self._live.stop()
            self._live = None
