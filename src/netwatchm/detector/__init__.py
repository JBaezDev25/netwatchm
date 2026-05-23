"""Threat detection modules."""
from .adult_domain import AdultDomainDetector
from .beaconing import BeaconingDetector
from .brute_force import BruteForceDetector
from .data_hog import DataHogDetector
from .dns_tunneling import DnsTunnelingDetector
from .exfiltration import ExfiltrationDetector
from .malware_domain import MalwareDomainDetector
from .new_ip import NewIPDetector
from .port_scan import PortScanDetector
from .tor_exit import TorExitDetector
from .tracker_domain import TrackerDomainDetector

__all__ = [
    "AdultDomainDetector",
    "BeaconingDetector",
    "BruteForceDetector",
    "DataHogDetector",
    "DnsTunnelingDetector",
    "ExfiltrationDetector",
    "MalwareDomainDetector",
    "NewIPDetector",
    "PortScanDetector",
    "TorExitDetector",
    "TrackerDomainDetector",
]
