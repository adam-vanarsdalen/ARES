"""
ARES external enrichment tools.

All lookups in this module are passive, non-fatal, and return normalized
results so pipeline phases can consume enrichment without coupling to a
specific upstream response shape.
"""

import ipaddress
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from utils.config import EXTERNAL_LOOKUP_TIMEOUT, REVERSE_IP_MAX_HOSTS
from utils.scope_validator import ScopeValidator


_KEV_CACHE: dict[str, dict] = {}
_KEV_CACHE_TS = 0.0
_KEV_CACHE_TTL = 24 * 60 * 60


def _empty_internetdb(ip: str, status: str = "failed", error: str = "") -> dict:
    return {
        "ip": ip or "",
        "ports": [],
        "hostnames": [],
        "vulns": [],
        "cpes": [],
        "tags": [],
        "source": "shodan_internetdb",
        "status": status,
        "error": error,
    }


def _empty_reverse_ip(query: str, status: str = "failed", error: str = "") -> dict:
    return {
        "query": query or "",
        "hostnames": [],
        "ownership_unverified": True,
        "source": "hackertarget_reverse_ip",
        "status": status,
        "error": error,
    }


def _empty_kev(cve_id: str, status: str = "failed", error: str = "") -> dict:
    """Return the normalized empty CISA KEV result."""
    return {
        "cve_id": cve_id or "",
        "in_kev": False,
        "vendor": "",
        "product": "",
        "date_added": "",
        "required_action": "",
        "source": "cisa_kev",
        "status": status,
        "error": error,
    }


def _empty_ip_reputation(ip: str, status: str = "failed", error: str = "") -> dict:
    """Return the normalized empty AbuseIPDB result."""
    return {
        "ip": ip or "",
        "abuse_confidence_score": 0,
        "is_tor": False,
        "is_public": False,
        "usage_type": "",
        "isp": "",
        "country_code": "",
        "total_reports": 0,
        "last_reported_at": "",
        "source": "abuseipdb",
        "status": status,
        "error": error,
    }


def _list(value) -> list:
    if not isinstance(value, list):
        return []
    return value


def kev_lookup(cve_id: str) -> dict:
    """Check a CVE against the cached CISA Known Exploited Vulnerabilities catalog."""
    normalized_cve = (cve_id or "").strip().upper()
    if not normalized_cve:
        return _empty_kev(normalized_cve, error="empty_cve_id")

    global _KEV_CACHE, _KEV_CACHE_TS
    now = time.time()
    if not _KEV_CACHE_TS or now - _KEV_CACHE_TS > _KEV_CACHE_TTL:
        req = urllib.request.Request(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            headers={"User-Agent": "ARES/1.0", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=EXTERNAL_LOOKUP_TIMEOUT) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
            entries = payload.get("vulnerabilities", [])
            if not isinstance(entries, list):
                raise ValueError("invalid_kev_catalog")
            _KEV_CACHE = {
                str(entry.get("cveID", "")).strip().upper(): entry
                for entry in entries
                if isinstance(entry, dict) and entry.get("cveID")
            }
            _KEV_CACHE_TS = time.time()
        except Exception as exc:
            return _empty_kev(normalized_cve, error=type(exc).__name__)

    entry = _KEV_CACHE.get(normalized_cve)
    if not entry:
        return _empty_kev(normalized_cve, status="not_found")
    return {
        "cve_id": normalized_cve,
        "in_kev": True,
        "vendor": str(entry.get("vendorProject") or ""),
        "product": str(entry.get("product") or ""),
        "date_added": str(entry.get("dateAdded") or ""),
        "required_action": str(entry.get("requiredAction") or ""),
        "source": "cisa_kev",
        "status": "success",
        "error": "",
    }


def ip_reputation_lookup(ip: str) -> dict:
    """Query AbuseIPDB for passive IP reputation when an API key is configured."""
    normalized_ip = (ip or "").strip()
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return _empty_ip_reputation(normalized_ip, status="skipped", error="no_api_key")

    url = (
        "https://api.abuseipdb.com/api/v2/check?ipAddress="
        + urllib.parse.quote(normalized_ip, safe="")
        + "&maxAgeInDays=90"
    )
    req = urllib.request.Request(
        url,
        headers={"Key": api_key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=EXTERNAL_LOOKUP_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
        data = payload.get("data", {})
        if not isinstance(data, dict):
            raise ValueError("invalid_abuseipdb_response")
        return {
            "ip": str(data.get("ipAddress") or normalized_ip),
            "abuse_confidence_score": int(data.get("abuseConfidenceScore") or 0),
            "is_tor": bool(data.get("isTor", False)),
            "is_public": bool(data.get("isPublic", False)),
            "usage_type": str(data.get("usageType") or ""),
            "isp": str(data.get("isp") or ""),
            "country_code": str(data.get("countryCode") or ""),
            "total_reports": int(data.get("totalReports") or 0),
            "last_reported_at": str(data.get("lastReportedAt") or ""),
            "source": "abuseipdb",
            "status": "success",
            "error": "",
        }
    except urllib.error.HTTPError as exc:
        return _empty_ip_reputation(normalized_ip, error=f"http_{exc.code}")
    except Exception as exc:
        return _empty_ip_reputation(normalized_ip, error=type(exc).__name__)


def internetdb_lookup(ip: str) -> dict:
    """
    Query Shodan InternetDB for passive IP enrichment.

    InternetDB requires no API key. Failures are intentionally non-fatal:
    callers should treat failed/no_data results as coverage gaps, not as
    assessment failures.
    """
    ip = (ip or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return _empty_internetdb(ip, error="invalid_ip")

    url = f"https://internetdb.shodan.io/{ip}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "ARES/1.0", "Accept": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=EXTERNAL_LOOKUP_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return _empty_internetdb(ip, status="no_data")
        return _empty_internetdb(ip, error=f"http_{exc.code}")
    except TimeoutError:
        return _empty_internetdb(ip, error="timeout")
    except socket.timeout:
        return _empty_internetdb(ip, error="timeout")
    except json.JSONDecodeError:
        return _empty_internetdb(ip, error="malformed_json")
    except Exception as exc:
        return _empty_internetdb(ip, error=type(exc).__name__)

    ports = []
    for port in _list(payload.get("ports")):
        try:
            ports.append(int(port))
        except (TypeError, ValueError):
            continue

    return {
        "ip": str(payload.get("ip") or ip),
        "ports": sorted(set(ports)),
        "hostnames": sorted({str(item) for item in _list(payload.get("hostnames")) if item}),
        "vulns": sorted({str(item) for item in _list(payload.get("vulns")) if item}),
        "cpes": sorted({str(item) for item in _list(payload.get("cpes")) if item}),
        "tags": sorted({str(item) for item in _list(payload.get("tags")) if item}),
        "source": "shodan_internetdb",
        "status": "success",
        "error": "",
    }


def _reverse_query_value(ip_or_domain: str, scope: ScopeValidator) -> tuple[str, str]:
    value = (ip_or_domain or "").strip()
    if not value:
        return "", "empty_query"
    parsed = urllib.parse.urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or value.split("/", 1)[0].strip()
    host = host.rstrip(".")
    try:
        ipaddress.ip_address(host)
        return host, ""
    except ValueError:
        pass
    scope.assert_in_scope(host)
    return host, ""


def reverse_ip_lookup(ip_or_domain: str, scope: ScopeValidator) -> dict:
    """
    Query HackerTarget reverse IP lookup for passive hostname enrichment.

    Reverse-IP ownership is inherently uncertain, so returned hostnames are
    informational only and must not expand active scope.
    """
    try:
        query, error = _reverse_query_value(ip_or_domain, scope)
    except Exception as exc:
        return _empty_reverse_ip(ip_or_domain, error=type(exc).__name__)
    if error:
        return _empty_reverse_ip(ip_or_domain, error=error)

    url = "https://api.hackertarget.com/reverseiplookup/?q=" + urllib.parse.quote(query, safe="")
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "ARES/1.0", "Accept": "text/plain"},
    )
    try:
        with urllib.request.urlopen(req, timeout=EXTERNAL_LOOKUP_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            return _empty_reverse_ip(query, status="failed", error="http_429")
        return _empty_reverse_ip(query, status="failed", error=f"http_{exc.code}")
    except TimeoutError:
        return _empty_reverse_ip(query, status="failed", error="timeout")
    except socket.timeout:
        return _empty_reverse_ip(query, status="failed", error="timeout")
    except Exception as exc:
        return _empty_reverse_ip(query, status="failed", error=type(exc).__name__)

    lowered = body.lower()
    if any(marker in lowered for marker in ("api count exceeded", "no dns a records", "error", "invalid ip")):
        if "api count exceeded" in lowered:
            return _empty_reverse_ip(query, status="no_data", error="api_count_exceeded")
        if "no dns a records" in lowered:
            return _empty_reverse_ip(query, status="no_data", error="no_dns_a_records")
        return _empty_reverse_ip(query, status="failed", error="upstream_error")

    hostnames = []
    for line in body.splitlines():
        host = line.strip().lower().rstrip(".")
        if not host or " " in host or "/" in host or ":" in host:
            continue
        hostnames.append(host)

    hostnames = sorted(dict.fromkeys(hostnames))[:REVERSE_IP_MAX_HOSTS]
    return {
        "query": query,
        "hostnames": hostnames,
        "ownership_unverified": True,
        "source": "hackertarget_reverse_ip",
        "status": "success" if hostnames else "no_data",
        "error": "",
    }
