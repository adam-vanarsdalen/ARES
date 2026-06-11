"""Privacy-preserving Have I Been Pwned domain exposure enrichment."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter

from utils.config import EXTERNAL_LOOKUP_TIMEOUT


def _sanitize_domain(domain: str) -> str:
    """Normalize a URL, email address, or host value to a bare domain."""
    value = (domain or "").strip()
    parsed = urllib.parse.urlparse(value if "://" in value else f"//{value}")
    return (parsed.hostname or "").lower().rstrip(".")


def _empty_hibp(domain: str, status: str = "failed", error: str = "") -> dict:
    """Return the normalized empty HIBP domain result."""
    return {
        "domain": domain or "",
        "breach_count": 0,
        "breached_aliases": 0,
        "top_breaches": [],
        "sample_aliases_redacted": 0,
        "source": "hibp_domain",
        "status": status,
        "error": error,
    }


def hibp_domain_lookup(domain: str) -> dict:
    """Check a domain for HIBP breach names while returning alias counts only."""
    normalized_domain = _sanitize_domain(domain)
    api_key = os.environ.get("HIBP_API_KEY", "").strip()
    if not api_key:
        return _empty_hibp(normalized_domain, status="skipped", error="no_api_key")

    url = (
        "https://haveibeenpwned.com/api/v3/breacheddomain/"
        + urllib.parse.quote(normalized_domain, safe="")
    )
    req = urllib.request.Request(
        url,
        headers={"hibp-api-key": api_key, "User-Agent": "ARES/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=EXTERNAL_LOOKUP_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
        if not isinstance(payload, dict):
            raise ValueError("invalid_hibp_response")
        breach_names = []
        breached_aliases = 0
        for aliases_breaches in payload.values():
            if not isinstance(aliases_breaches, list) or not aliases_breaches:
                continue
            breached_aliases += 1
            breach_names.extend(str(name) for name in aliases_breaches if name)
        counts = Counter(breach_names)
        top_breaches = [
            name
            for name, _count in sorted(
                counts.items(),
                key=lambda item: (-item[1], item[0]),
            )[:5]
        ]
        return {
            "domain": normalized_domain,
            "breach_count": len(counts),
            "breached_aliases": breached_aliases,
            "top_breaches": top_breaches,
            "sample_aliases_redacted": breached_aliases,
            "source": "hibp_domain",
            "status": "success",
            "error": "",
        }
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return _empty_hibp(normalized_domain, status="not_found")
        if exc.code == 429:
            return _empty_hibp(normalized_domain, status="rate_limited", error="http_429")
        return _empty_hibp(normalized_domain, error=f"http_{exc.code}")
    except Exception as exc:
        return _empty_hibp(normalized_domain, error=type(exc).__name__)


def hibp_bulk_domain_lookup(domains: list[str]) -> list[dict]:
    """Check multiple HIBP domains with a 1.5-second inter-request delay."""
    results = []
    for index, domain in enumerate(domains):
        try:
            results.append(hibp_domain_lookup(domain))
        except Exception as exc:
            results.append(_empty_hibp(_sanitize_domain(domain), error=type(exc).__name__))
        if index < len(domains) - 1:
            time.sleep(1.5)
    return results
