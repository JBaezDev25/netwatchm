"""Sound alert handler: pygame WAV playback; silent when headless or unavailable."""
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

from ..config import SoundAlertConfig
from ..models import Alert, ThreatLevel
from .base import AlertHandler

logger = logging.getLogger(__name__)


class SoundAlert(AlertHandler):
    """Play a WAV sound on alerts at or above min_level.

    Silently fails when:
    - pygame is not installed
    - Running headless (no DISPLAY env var on Linux)
    - Sound file not found
    """

    def __init__(self, config: SoundAlertConfig) -> None:
        self._enabled = config.enabled
        self._min_level = ThreatLevel[config.min_level]
        self._wav_path = Path(config.file)
        self._mixer_ready = False

        if not self._enabled:
            return

        # Headless check
        if os.environ.get("DISPLAY") is None and os.environ.get("WAYLAND_DISPLAY") is None:
            import sys
            if sys.platform != "win32":
                logger.debug("No display detected; sound alerts disabled")
                self._enabled = False
                return

        try:
            import pygame  # type: ignore[import]
            pygame.mixer.pre_init(44100, -16, 2, 512)
            pygame.mixer.init()
            self._mixer_ready = True
            self._pygame = pygame
            if not self._wav_path.exists():
                logger.warning("Alert sound file not found: %s", self._wav_path)
                self._enabled = False
        except Exception as exc:  # noqa: BLE001
            logger.debug("Sound alert unavailable: %s", exc)
            self._enabled = False

    async def send(self, alert: Alert) -> None:
        if not self._enabled or not self._mixer_ready:
            return
        if alert.level < self._min_level:
            return

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._play)

    def _play(self) -> None:
        try:
            sound = self._pygame.mixer.Sound(str(self._wav_path))
            sound.play()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Sound play error: %s", exc)
