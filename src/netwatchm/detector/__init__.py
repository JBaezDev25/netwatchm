"""Threat detection modules."""
from .adult_domain import AdultDomainDetector
from .brute_force import BruteForceDetector
from .data_hog import DataHogDetector
from .exfiltration import ExfiltrationDetector
from .new_ip import NewIPDetector
from .port_scan import PortScanDetector
from .tor_exit import TorExitDetector
from .tracker_domain import TrackerDomainDetector

__all__ = [
    "AdultDomainDetector",
    "BruteForceDetector",
    "DataHogDetector",
    "ExfiltrationDetector",
    "NewIPDetector",
    "PortScanDetector",
    "TorExitDetector",
    "TrackerDomainDetector",
]
