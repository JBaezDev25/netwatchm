"""GRC: governance, risk & compliance scoring for the monitored fleet.

Pure-Python, data-source agnostic. The web server feeds it inventory +
event/incident data; the engine returns per-device risk scores and a
CIS-aligned control assessment for the /grc.html portal.
"""
from .risk import (
    ControlResult,
    DeviceRisk,
    assess_controls,
    assess_device,
    risk_level,
)

__all__ = [
    "ControlResult",
    "DeviceRisk",
    "assess_controls",
    "assess_device",
    "risk_level",
]
