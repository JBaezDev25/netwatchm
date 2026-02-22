"""Abstract base class for threat detectors."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Alert, Packet


class Detector(ABC):
    """Base class for all threat detectors.

    Each detector maintains a sliding window of observations and fires
    an Alert when a threshold is exceeded.
    """

    @abstractmethod
    def process(self, packet: Packet) -> Alert | None:
        """Process a single packet and return an Alert if a threat is detected."""
        ...

    @abstractmethod
    def flush_expired(self) -> None:
        """Remove stale entries from the sliding window. Called every second."""
        ...
