"""Risk scoring + CIS-aligned control assessment.

Two independent halves:

* ``assess_device`` — folds a device's network exposure, recent alert
  activity, and (for public IPs) threat-intel verdict into a 0–100 risk score
  with a level band and concrete recommendations.
* ``assess_controls`` — evaluates the whole fleet against a small catalogue of
  CIS-Controls-v8-aligned checks and returns a pass/warn/fail per control plus
  an overall compliance percentage. This is the GRC "risk register" backing
  the /grc.html portal.

No I/O here — the caller supplies plain dicts/values, which keeps it unit
testable and reusable from the CLI or the web server.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Ports that materially raise a device's exposure, with a risk weight each.
# Cleartext / legacy admin services weigh heaviest.
RISKY_PORTS: dict[int, tuple[str, int]] = {
    21: ("FTP", 15),
    23: ("Telnet", 25),
    25: ("SMTP", 6),
    135: ("MSRPC", 10),
    139: ("NetBIOS", 12),
    445: ("SMB", 18),
    161: ("SNMP", 12),
    512: ("rexec", 20),
    1433: ("MSSQL", 12),
    3306: ("MySQL", 10),
    3389: ("RDP", 20),
    5432: ("PostgreSQL", 10),
    5900: ("VNC", 18),
}

# Remote-admin services that should not be exposed by an unverified device.
REMOTE_ADMIN_PORTS = {22, 23, 3389, 5900}

_LEVEL_FROM_ALERT = {
    "CRITICAL": 40,
    "HIGH": 30,
    "MEDIUM": 15,
    "LOW": 5,
    "": 0,
    None: 0,
}

_INTEL_SCORE = {"malicious": 40, "suspicious": 20}

RISK_LEVELS = ("low", "medium", "high", "critical")


def risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


@dataclass
class DeviceRisk:
    ip: str
    score: int
    level: str
    exposure: int
    threat: int
    intel: int
    risky_ports: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    label: str = ""
    verified: bool = False

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "label": self.label,
            "verified": self.verified,
            "score": self.score,
            "level": self.level,
            "factors": {
                "exposure": self.exposure,
                "threat": self.threat,
                "intel": self.intel,
            },
            "risky_ports": self.risky_ports,
            "recommendations": self.recommendations,
        }


def assess_device(
    *,
    ip: str,
    ports: list[int] | set[int] | None = None,
    alert_count: int = 0,
    max_alert_level: str | None = None,
    intel_verdict: str = "unknown",
    verified: bool = False,
    is_external: bool = False,
    label: str = "",
) -> DeviceRisk:
    """Score a single device's risk (0–100) from its exposure + activity."""
    ports = set(ports or [])

    risky = []
    exposure = 0
    for p in sorted(ports):
        if p in RISKY_PORTS:
            name, weight = RISKY_PORTS[p]
            risky.append(f"{p}/{name}")
            exposure += weight
    # Broad attack surface: a sliver of risk per open port beyond a handful.
    exposure += max(0, len(ports) - 5)
    exposure = min(exposure, 60)

    threat = _LEVEL_FROM_ALERT.get((max_alert_level or "").upper(), 0)
    threat += min(alert_count, 10) * 2
    threat = min(threat, 55)

    intel = _INTEL_SCORE.get(intel_verdict, 0) if is_external else 0

    raw = exposure + threat + intel
    # A verified/known-good device carries less residual risk for the same
    # exposure — operators have accepted it.
    if verified:
        raw = int(raw * 0.85)
    score = max(0, min(100, raw))

    recs = []
    if risky:
        recs.append(f"Close or firewall risky services: {', '.join(risky)}")
    if intel:
        recs.append(f"Threat-intel flagged this IP as {intel_verdict}; investigate the peer")
    if threat >= 30:
        recs.append("Recent high-severity alerts — review incidents for this device")
    if not verified and score >= 25:
        recs.append("Device is unverified; confirm ownership and mark verified in inventory")
    if not recs:
        recs.append("No elevated risk indicators")

    return DeviceRisk(
        ip=ip,
        score=score,
        level=risk_level(score),
        exposure=exposure,
        threat=threat,
        intel=intel,
        risky_ports=risky,
        recommendations=recs,
        label=label,
        verified=verified,
    )


@dataclass
class ControlResult:
    control_id: str
    framework: str
    title: str
    category: str
    status: str            # "pass" | "warn" | "fail"
    detail: str
    affected: list[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "framework": self.framework,
            "title": self.title,
            "category": self.category,
            "status": self.status,
            "detail": self.detail,
            "affected": self.affected,
            "remediation": self.remediation,
        }


def assess_controls(
    devices: list[dict],
    *,
    events_present: bool = True,
    monitor_active: bool = True,
) -> dict:
    """Evaluate the fleet against CIS-aligned controls.

    ``devices`` is a list of dicts with keys: ip, ports (list[int]),
    verified (bool), label (str), and risk (a DeviceRisk.to_dict()).
    Returns ``{"controls": [...], "compliance": int, "summary": {...}}``.
    """
    results: list[ControlResult] = []

    # CIS 1 — Inventory and control of enterprise assets
    total = len(devices)
    unverified = [d["ip"] for d in devices if not d.get("verified")]
    unlabeled = [d["ip"] for d in devices if not (d.get("label") or "").strip()]
    if total == 0:
        status, detail = "warn", "No devices in inventory yet"
    else:
        ratio = (total - len(unverified)) / total
        if ratio >= 0.9:
            status = "pass"
        elif ratio >= 0.5:
            status = "warn"
        else:
            status = "fail"
        detail = (f"{total - len(unverified)}/{total} devices verified, "
                  f"{len(unlabeled)} unlabeled")
    results.append(ControlResult(
        "1.1", "CIS v8", "Establish & maintain a detailed asset inventory",
        "Inventory", status, detail, unverified[:50],
        "Label and mark every known device as verified in /inventory.html",
    ))

    # CIS 4 — Secure configuration: cleartext / legacy services exposed
    cleartext = {21, 23, 161, 512}
    affected = sorted({
        d["ip"] for d in devices
        if cleartext & set(d.get("ports", []))
    })
    results.append(ControlResult(
        "4.8", "CIS v8", "Uninstall or disable unnecessary services",
        "Secure Config", "fail" if affected else "pass",
        (f"{len(affected)} device(s) expose cleartext/legacy services"
         if affected else "No cleartext/legacy services detected"),
        affected[:50],
        "Disable FTP/Telnet/SNMP/rexec or restrict them with firewall rules",
    ))

    # CIS 6 — Access control: unverified devices exposing remote-admin ports
    admin_exposed = sorted({
        d["ip"] for d in devices
        if not d.get("verified") and (REMOTE_ADMIN_PORTS & set(d.get("ports", [])))
    })
    results.append(ControlResult(
        "6.4", "CIS v8", "Restrict remote administrative access",
        "Access Control", "fail" if admin_exposed else "pass",
        (f"{len(admin_exposed)} unverified device(s) expose SSH/RDP/VNC/Telnet"
         if admin_exposed else "No unverified remote-admin exposure"),
        admin_exposed[:50],
        "Verify these hosts or block remote-admin ports at the firewall",
    ))

    # CIS 8 — Audit log management
    results.append(ControlResult(
        "8.2", "CIS v8", "Collect audit logs",
        "Logging", "pass" if events_present else "warn",
        "Alert event logging active" if events_present
        else "No alert events recorded yet",
        [], "Ensure the event store handler stays enabled",
    ))

    # CIS 13 — Network monitoring & defense: critical-risk devices present
    critical = sorted({
        d["ip"] for d in devices
        if (d.get("risk", {}).get("level")) in ("high", "critical")
    })
    results.append(ControlResult(
        "13.1", "CIS v8", "Centralize security event monitoring",
        "Network Defense",
        "pass" if monitor_active and not critical else
        ("fail" if critical else "warn"),
        (f"{len(critical)} device(s) at high/critical risk"
         if critical else "Monitoring active; no high-risk devices"),
        critical[:50],
        "Triage high-risk devices in /incidents.html and reduce their exposure",
    ))

    passed = sum(1 for r in results if r.status == "pass")
    compliance = round(passed / len(results) * 100) if results else 0
    summary = {
        "total_controls": len(results),
        "passed": passed,
        "warnings": sum(1 for r in results if r.status == "warn"),
        "failed": sum(1 for r in results if r.status == "fail"),
        "devices": total,
    }
    return {
        "controls": [r.to_dict() for r in results],
        "compliance": compliance,
        "summary": summary,
    }
