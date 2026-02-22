"""Inventory mode: full-screen Rich table of all discovered devices."""
from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..inventory.exporter import export_inventory
from ..inventory.store import DeviceStore
from ..models import DeviceRecord, ThreatLevel

_LEVEL_STYLE = {
    ThreatLevel.LOW: "green",
    ThreatLevel.MEDIUM: "yellow",
    ThreatLevel.HIGH: "red",
    ThreatLevel.CRITICAL: "bold red",
}


class InventoryView:
    """Full-screen inventory table with live filter and CSV export."""

    def __init__(self, store: DeviceStore, console: Console | None = None) -> None:
        self._store = store
        self._console = console or Console()
        self._filter: str = ""
        self._notification: str = ""
        self._notification_until: float = 0.0
        self._live: Live | None = None
        self._records: list[DeviceRecord] = []

    def set_filter(self, query: str) -> None:
        self._filter = query

    def clear_filter(self) -> None:
        self._filter = ""

    def append_filter_char(self, ch: str) -> None:
        self._filter += ch

    def backspace_filter(self) -> None:
        self._filter = self._filter[:-1]

    async def refresh_records(self) -> None:
        self._records = await self._store.get_all(self._filter or None)

    def export_csv(self, export_dir: str = ".") -> str:
        ts = datetime.now().strftime("%Y%m%dT%H%M%S")
        filename = f"netwatchm-inventory-{ts}.csv"
        path = Path(export_dir) / filename
        export_inventory(self._records, path)
        self._notification = f"Exported: {path}"
        self._notification_until = time.time() + 2.0
        return str(path)

    def _build_table(self) -> Table:
        table = Table(
            show_header=True,
            header_style="bold cyan",
            box=None,
            expand=True,
            padding=(0, 1),
        )
        table.add_column("IP", no_wrap=True, min_width=15)
        table.add_column("Hostname", no_wrap=True, min_width=20)
        table.add_column("MAC", no_wrap=True, min_width=18)
        table.add_column("Vendor", no_wrap=True, min_width=12)
        table.add_column("First Seen", width=19)
        table.add_column("Last Seen", width=19)
        table.add_column("↑ Sent", justify="right", width=10)
        table.add_column("↓ Recv", justify="right", width=10)
        table.add_column("Ports", min_width=20)
        table.add_column("Level", width=8)

        for rec in self._records:
            style = _LEVEL_STYLE.get(rec.threat_level, "")
            ports = ";".join(str(p) for p in sorted(rec.ports_observed)[:10])
            if len(rec.ports_observed) > 10:
                ports += "…"
            table.add_row(
                rec.ip,
                rec.hostname or "—",
                rec.mac or "—",
                rec.vendor or "—",
                rec.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
                rec.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                _fmt_bytes(rec.bytes_sent),
                _fmt_bytes(rec.bytes_received),
                ports or "—",
                f"[{style}]{rec.threat_level.name}[/{style}]",
                style=style,
            )
        return table

    def _build_header(self) -> Panel:
        count = len(self._records)
        text = Text.assemble(
            ("Device Inventory", "bold cyan"),
            ("  |  ", "dim"),
            (f"{count} device{'s' if count != 1 else ''}", "cyan"),
            ("  |  Filter: ", "dim"),
            (self._filter or "(none)", "yellow" if self._filter else "dim"),
        )
        return Panel(text, style="on grey7", height=3)

    def _build_footer(self) -> Panel:
        notif = ""
        if self._notification and time.time() < self._notification_until:
            notif = f"  [green]{self._notification}[/green]"
        text = Text.from_markup(
            f"  [bold yellow][/] Search  [bold yellow][E][/] Export CSV  "
            f"[bold yellow][M][/] Monitor  [bold red][Q][/] Quit{notif}"
        )
        return Panel(text, style="on grey7", height=3)

    def build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(self._build_header(), name="header", size=3),
            Layout(Panel(self._build_table(), title="Inventory", border_style="cyan"), name="main"),
            Layout(self._build_footer(), name="footer", size=3),
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


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n //= 1024
    return f"{n:.0f} TB"
