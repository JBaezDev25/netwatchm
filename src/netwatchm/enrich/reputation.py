"""Threat-intel reputation lookups for incident enrichment.

Queries free-tier providers (GreyNoise community, AbuseIPDB, VirusTotal) plus
the local GeoLite2 DB, then folds the per-provider signals into a single
verdict: "malicious" | "suspicious" | "benign" | "unknown".

Dependency-light on purpose — uses urllib so the monitor host needs no extra
packages. Every provider call is best-effort: a network/parse failure leaves
that provider's entry as an ``error`` and never breaks the incident pipeline.

API keys are passed in by the caller (sourced from env vars in config); this
module never reads YAML or hardcodes a secret.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field

log = logging.getLogger("netwatchm.enrich")

DEFAULT_GEOIP_DB = "/var/lib/netwatchm/GeoLite2-City.mmdb"

VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_BENIGN = "benign"
VERDICT_UNKNOWN = "unknown"

# Ranking used to pick the worst verdict across providers.
_RANK = {
    VERDICT_UNKNOWN: 0,
    VERDICT_BENIGN: 1,
    VERDICT_SUSPICIOUS: 2,
    VERDICT_MALICIOUS: 3,
}


@dataclass
class ReputationResult:
    ip: str
    verdict: str = VERDICT_UNKNOWN
    score: int = 0                       # 0-100 worst abuse/malicious score seen
    is_private: bool = False
    geo_country: str = ""
    geo_city: str = ""
    geo_asn: str = ""
    summary: str = ""
    providers: dict = field(default_factory=dict)  # name -> raw normalized dict

    def to_dict(self) -> dict:
        return asdict(self)


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True


def _http_get_json(url: str, headers: dict, timeout: int) -> dict:
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _geoip(ip: str, db_path: str) -> dict:
    try:
        import geoip2.database
        import geoip2.errors

        from pathlib import Path
        if not Path(db_path).exists():
            return {}
        with geoip2.database.Reader(db_path) as reader:
            try:
                r = reader.city(ip)
            except geoip2.errors.AddressNotFoundError:
                return {}
            return {
                "country": (r.country.name or r.registered_country.name or ""),
                "city": (r.city.name or ""),
                "asn": str(r.traits.autonomous_system_number or ""),
            }
    except Exception as exc:  # noqa: BLE001
        log.debug("geoip lookup failed for %s: %s", ip, exc)
        return {}


def _greynoise(ip: str, key: str, timeout: int) -> dict:
    """GreyNoise community endpoint. No key required; key raises rate limits."""
    headers = {"Accept": "application/json", "User-Agent": "netwatchm"}
    if key:
        headers["key"] = key
    try:
        data = _http_get_json(
            f"https://api.greynoise.io/v3/community/{ip}", headers, timeout
        )
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"verdict": VERDICT_UNKNOWN, "noise": False, "note": "not observed"}
        return {"error": f"HTTP {exc.code}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}

    classification = (data.get("classification") or "").lower()
    if classification == "malicious":
        verdict = VERDICT_MALICIOUS
    elif classification == "benign":
        verdict = VERDICT_BENIGN
    elif data.get("noise"):
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_UNKNOWN
    return {
        "verdict": verdict,
        "classification": classification or "unknown",
        "noise": bool(data.get("noise")),
        "name": data.get("name", ""),
        "last_seen": data.get("last_seen", ""),
    }


def _abuseipdb(ip: str, key: str, timeout: int) -> dict:
    if not key:
        return {"error": "no API key (set NETWATCHM_ABUSEIPDB_KEY)"}
    headers = {"Accept": "application/json", "Key": key}
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    try:
        data = _http_get_json(url, headers, timeout).get("data", {})
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}

    score = int(data.get("abuseConfidenceScore", 0) or 0)
    if score >= 50:
        verdict = VERDICT_MALICIOUS
    elif score >= 10:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_BENIGN
    return {
        "verdict": verdict,
        "score": score,
        "total_reports": int(data.get("totalReports", 0) or 0),
        "country": data.get("countryCode", ""),
        "isp": data.get("isp", ""),
        "domain": data.get("domain", ""),
    }


def _virustotal(ip: str, key: str, timeout: int) -> dict:
    if not key:
        return {"error": "no API key (set NETWATCHM_VT_KEY)"}
    headers = {"Accept": "application/json", "x-apikey": key}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        attrs = _http_get_json(url, headers, timeout).get("data", {}).get("attributes", {})
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}

    stats = attrs.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    if malicious >= 3:
        verdict = VERDICT_MALICIOUS
    elif malicious >= 1 or suspicious >= 2:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_BENIGN
    return {
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": int(stats.get("harmless", 0) or 0),
        "reputation": int(attrs.get("reputation", 0) or 0),
        "asn": str(attrs.get("asn", "") or ""),
        "country": attrs.get("country", ""),
    }


def enrich_ip(ip: str, cfg) -> ReputationResult:
    """Synchronous enrichment of a single IP. Call from a thread executor.

    ``cfg`` is a ``ForensicsConfig`` (duck-typed: needs the provider flags,
    keys, intel_timeout, and a geoip db path resolver).
    """
    result = ReputationResult(ip=ip)

    if _is_private(ip):
        result.is_private = True
        result.verdict = VERDICT_BENIGN
        result.summary = "Private/local address — no external reputation"
        return result

    geo = _geoip(ip, getattr(cfg, "geoip_db", DEFAULT_GEOIP_DB))
    if geo:
        result.geo_country = geo.get("country", "")
        result.geo_city = geo.get("city", "")
        result.geo_asn = geo.get("asn", "")

    if not getattr(cfg, "intel_enabled", True):
        result.summary = _summarize(result, geo)
        return result

    timeout = getattr(cfg, "intel_timeout", 8)
    worst = VERDICT_UNKNOWN
    worst_score = 0

    if getattr(cfg, "greynoise", True):
        gn = _greynoise(ip, getattr(cfg, "greynoise_key", ""), timeout)
        result.providers["greynoise"] = gn
        worst = _max_verdict(worst, gn.get("verdict"))

    if getattr(cfg, "abuseipdb", True):
        ab = _abuseipdb(ip, getattr(cfg, "abuseipdb_key", ""), timeout)
        result.providers["abuseipdb"] = ab
        worst = _max_verdict(worst, ab.get("verdict"))
        worst_score = max(worst_score, int(ab.get("score", 0) or 0))

    if getattr(cfg, "virustotal", True):
        vt = _virustotal(ip, getattr(cfg, "virustotal_key", ""), timeout)
        result.providers["virustotal"] = vt
        worst = _max_verdict(worst, vt.get("verdict"))
        # VT malicious-engine count scaled into a rough 0-100 score
        worst_score = max(worst_score, min(100, int(vt.get("malicious", 0) or 0) * 10))

    result.verdict = worst
    result.score = worst_score
    result.summary = _summarize(result, geo)
    return result


def _max_verdict(current: str, candidate: str | None) -> str:
    if not candidate:
        return current
    return candidate if _RANK.get(candidate, 0) > _RANK.get(current, 0) else current


def _summarize(result: ReputationResult, geo: dict) -> str:
    parts = [f"verdict={result.verdict}"]
    if result.score:
        parts.append(f"score={result.score}")
    if geo.get("country"):
        loc = geo["country"]
        if geo.get("city"):
            loc = f"{geo['city']}, {loc}"
        parts.append(loc)
    if geo.get("asn"):
        parts.append(f"ASN{geo['asn']}")
    return " · ".join(parts)
