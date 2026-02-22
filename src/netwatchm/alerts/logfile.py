"""Log file alert handler: rotating JSON line logger."""
from __future__ import annotations

import json
import logging
import logging.handlers
from pathlib import Path

from ..config import LogAlertConfig
from ..models import Alert
from .base import AlertHandler


class LogFileAlert(AlertHandler):
    """Write alert events as JSON lines to a rotating log file."""

    def __init__(self, config: LogAlertConfig) -> None:
        self._enabled = config.enabled
        if not self._enabled:
            return

        log_path = Path(config.path)
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.handlers.RotatingFileHandler(
                log_path,
                maxBytes=config.max_bytes,
                backupCount=config.backup_count,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger = logging.getLogger("netwatchm.alerts.file")
            self._logger.setLevel(logging.INFO)
            self._logger.addHandler(handler)
            self._logger.propagate = False
        except OSError as exc:
            logging.getLogger(__name__).warning(
                "Cannot open log file %s: %s. Log alerts disabled.", log_path, exc
            )
            self._enabled = False

    async def send(self, alert: Alert) -> None:
        if not self._enabled:
            return
        record = {
            "timestamp": alert.timestamp.isoformat(),
            "alert_type": alert.alert_type,
            "level": alert.level.name,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "description": alert.description,
        }
        self._logger.info(json.dumps(record))
