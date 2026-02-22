"""Terminal alert handler: Rich colored console output."""
from __future__ import annotations

from rich.console import Console

from ..models import Alert, ThreatLevel
from .base import AlertHandler

_LEVEL_ICON = {
    ThreatLevel.LOW: "●",
    ThreatLevel.MEDIUM: "▲",
    ThreatLevel.HIGH: "■",
    ThreatLevel.CRITICAL: "✖",
}


class TerminalAlert(AlertHandler):
    """Print colored alert messages to the terminal using Rich."""

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console(stderr=True)

    async def send(self, alert: Alert) -> None:
        icon = _LEVEL_ICON.get(alert.level, "●")
        color = alert.level.color
        ts = alert.timestamp.strftime("%H:%M:%S")
        self._console.print(
            f"[dim]{ts}[/dim] [{color}]{icon} {alert.level.name}[/{color}] "
            f"[bold]{alert.alert_type}[/bold] — {alert.description}"
        )
