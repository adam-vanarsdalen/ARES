"""Passive command-and-control IOC checks using public abuse.ch feeds."""

from __future__ import annotations

import ipaddress
import json
import time
import urllib.parse
import urllib.request

from utils.config import EXTERNAL_LOOKUP_TIMEOUT


_FEODO_CACHE: set[str] = set()
_FEODO_TS = 0.0
_FEODO_ERROR = ""
_URLHAUS_CACHE: set[str] = set()
_URLHAUS_TS = 0.0
_URLHAUS_ERROR = ""
_CACHE_TTL = 60 * 60


def _load_feodo_blocklist() -> set[str]:
    """Fetch and cache the Feodo Tracker IP blocklist for one hour."""
    global _FEODO_CACHE, _FEODO_TS, _FEODO_ERROR
    if _FEODO_TS and time.time() - _FEODO_TS <= _CACHE_TTL:
        return _FEODO_CACHE
    req = urllib.request.Request(
        "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        headers={"User-Agent": "ARES/1.0", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=EXTERNAL_LOOKUP_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
        if not isinstance(payload, list):
            raise ValueError("invalid_feodo_response")
        _FEODO_CACHE = {
            str(entry.get("ip_address", "")).strip()
            for entry in payload
            if isinstance(entry, dict) and entry.get("ip_address")
        }
        _FEODO_TS = time.time()
        _FEODO_ERROR = ""
    except Exception as exc:
        _FEODO_ERROR = type(exc).__name__
    return _FEODO_CACHE


def _load_urlhaus_domains() -> set[str]:
    """Fetch and cache hostnames from the URLhaus recent URL feed for one hour."""
    global _URLHAUS_CACHE, _URLHAUS_TS, _URLHAUS_ERROR
    if _URLHAUS_TS and time.time() - _URLHAUS_TS <= _CACHE_TTL:
        return _URLHAUS_CACHE
    req = urllib.request.Request(
        "https://urlhaus.abuse.ch/downloads/text_recent/",
        headers={"User-Agent": "ARES/1.0", "Accept": "text/plain"},
    )
    try:
        with urllib.request.urlopen(req, timeout=EXTERNAL_LOOKUP_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
        domains = set()
        for line in body.splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            parsed = urllib.parse.urlparse(value)
            if parsed.hostname:
                domains.add(parsed.hostname.lower().rstrip("."))
        _URLHAUS_CACHE = domains
        _URLHAUS_TS = time.time()
        _URLHAUS_ERROR = ""
    except Exception as exc:
        _URLHAUS_ERROR = type(exc).__name__
    return _URLHAUS_CACHE


def _normalize_indicator(indicator: str) -> tuple[str, str]:
    """Normalize an IOC and classify it as an IP address, domain, or unknown."""
    value = (indicator or "").strip()
    parsed = urllib.parse.urlparse(value if "://" in value else f"//{value}")
    normalized = (parsed.hostname or "").lower().rstrip(".")
    try:
        ipaddress.ip_address(normalized)
        return normalized, "ip"
    except ValueError:
        pass
    if normalized and all(
        part and part.replace("-", "").isalnum()
        for part in normalized.split(".")
    ):
        return normalized, "domain"
    return normalized or value.rstrip("/"), "unknown"


def check_c2_ioc(indicator: str) -> dict:
    """Check one normalized IP address or hostname against Feodo and URLhaus."""
    normalized, indicator_type = _normalize_indicator(indicator)
    try:
        feodo = _load_feodo_blocklist()
        urlhaus = _load_urlhaus_domains()
        matched_feeds = []
        if normalized in feodo:
            matched_feeds.append("feodo_tracker")
        if normalized in urlhaus:
            matched_feeds.append("urlhaus")
        errors = [
            f"feodo_tracker:{_FEODO_ERROR}" if _FEODO_ERROR else "",
            f"urlhaus:{_URLHAUS_ERROR}" if _URLHAUS_ERROR else "",
        ]
        errors = [error for error in errors if error]
        return {
            "indicator": normalized,
            "is_c2_ioc": bool(matched_feeds),
            "matched_feeds": matched_feeds,
            "indicator_type": indicator_type,
            "source": "c2_ioc_check",
            "status": "failed" if errors else "success",
            "error": ";".join(errors),
        }
    except Exception as exc:
        return {
            "indicator": normalized,
            "is_c2_ioc": False,
            "matched_feeds": [],
            "indicator_type": indicator_type,
            "source": "c2_ioc_check",
            "status": "failed",
            "error": type(exc).__name__,
        }


def check_c2_ioc_bulk(indicators: list[str]) -> list[dict]:
    """Check multiple C2 indicators without allowing one failure to stop the batch."""
    results = []
    for indicator in indicators:
        try:
            results.append(check_c2_ioc(indicator))
        except Exception as exc:
            normalized, indicator_type = _normalize_indicator(indicator)
            results.append({
                "indicator": normalized,
                "is_c2_ioc": False,
                "matched_feeds": [],
                "indicator_type": indicator_type,
                "source": "c2_ioc_check",
                "status": "failed",
                "error": type(exc).__name__,
            })
    return results
