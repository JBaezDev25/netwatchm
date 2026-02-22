"""Abstract base class for alert handlers."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Alert


class AlertHandler(ABC):
    """Base class for all alert delivery mechanisms."""

    @abstractmethod
    async def send(self, alert: Alert) -> None:
        """Deliver the alert."""
        ...
