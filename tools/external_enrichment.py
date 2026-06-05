"""
ARES external enrichment tools.

All lookups in this module are passive, non-fatal, and return normalized
results so pipeline phases can consume enrichment without coupling to a
specific upstream response shape.
"""

import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request

from utils.config import EXTERNAL_LOOKUP_TIMEOUT, REVERSE_IP_MAX_HOSTS
from utils.scope_validator import ScopeValidator


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


def _list(value) -> list:
    if not isinstance(value, list):
        return []
    return value


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
