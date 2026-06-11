"""
ARES — Certificate Transparency Intelligence
Queries crt.sh (public CT log aggregator) to discover every subdomain
that has ever had a TLS certificate issued — including dev, staging, and
internal environments the target forgot about.

This is PASSIVE — never touches the target directly.
"""

import json
import logging
import urllib.request
import urllib.parse
import socket
import concurrent.futures
from utils.scope_validator import ScopeValidator


logger = logging.getLogger(__name__)

_DNS_MAX_WORKERS = 20
_DNS_LOOKUP_TIMEOUT_S = 2.5


def query_crt_sh(domain: str) -> list[dict]:
    """
    Query crt.sh certificate transparency logs for a domain.
    Returns list of {subdomain, issuer, not_before, not_after} dicts.
    """
    url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
    req = urllib.request.Request(url, headers={
        "User-Agent": "ARES/1.0 Security Research",
        "Accept": "application/json"
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        logger.error("crt.sh query failed for domain=%r url=%r: %s", domain, url, e, exc_info=True)
        return []

    seen = set()
    results = []
    for entry in data:
        name = entry.get("name_value", "")
        # CT logs can have multi-line name_value with multiple SANs
        for raw in name.split("\n"):
            sub = raw.strip()
            if sub.startswith("*."):
                sub = sub[2:]
            sub = sub.lstrip(".")
            if not sub or sub in seen:
                continue
            # Filter to only subdomains of the target domain
            sub_l = sub.lower()
            dom_l = domain.lower()
            if not sub_l.endswith(f".{dom_l}") and sub_l != dom_l:
                continue
            seen.add(sub)
            results.append({
                "subdomain": sub,
                "issuer": entry.get("issuer_name", ""),
                "not_before": entry.get("not_before", ""),
                "not_after": entry.get("not_after", ""),
                "cert_id": entry.get("id")
            })

    return results


def resolve_ct_subdomains(ct_results: list[dict], scope: ScopeValidator) -> list[dict]:
    """
    Attempt DNS resolution on each CT-discovered subdomain.
    Returns enriched list with IP addresses and live status.
    """
    # Preserve stable/deterministic ordering: results align to the input CT order.
    allowed: list[tuple[int, dict]] = []
    for idx, entry in enumerate(ct_results):
        sub = entry.get("subdomain")
        if not sub:
            continue
        try:
            scope.assert_in_scope(sub)
        except ValueError:
            continue
        allowed.append((idx, entry))

    # Per-run DNS cache to avoid duplicate lookups.
    dns_cache: dict[str, tuple[str | None, bool]] = {}

    def _resolve(subdomain: str) -> tuple[str | None, bool]:
        if subdomain in dns_cache:
            return dns_cache[subdomain]
        try:
            ip = socket.gethostbyname(subdomain)
            res = (ip, True)
        except socket.gaierror:
            res = (None, False)
        dns_cache[subdomain] = res
        return res

    enriched_by_index: dict[int, dict] = {}
    max_workers = min(_DNS_MAX_WORKERS, max(1, len(allowed)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_by_sub: dict[str, concurrent.futures.Future] = {}
        futures: list[tuple[int, str, dict, concurrent.futures.Future]] = []
        for idx, entry in allowed:
            sub = entry["subdomain"]
            fut = future_by_sub.get(sub)
            if fut is None:
                fut = ex.submit(_resolve, sub)
                future_by_sub[sub] = fut
            futures.append((idx, sub, entry, fut))

        for idx, sub, entry, fut in futures:
            result = dict(entry)
            try:
                ip, live = fut.result(timeout=_DNS_LOOKUP_TIMEOUT_S)
                result["ip"] = ip
                result["live"] = live
            except concurrent.futures.TimeoutError:
                logger.error("DNS resolution timed out for %r", sub, exc_info=True)
                result["ip"] = None
                result["live"] = False
            except Exception as e:
                logger.error("DNS resolution failed for %r: %s", sub, e, exc_info=True)
                result["ip"] = None
                result["live"] = False
            enriched_by_index[idx] = result

    return [enriched_by_index[i] for i in sorted(enriched_by_index.keys())]


def cert_transparency_recon(domain: str, scope: ScopeValidator) -> dict:
    """
    Full CT recon: query crt.sh + resolve all discovered subdomains.
    Returns structured results with live vs. dead subdomains.
    """
    scope.assert_in_scope(domain)

    raw = query_crt_sh(domain)
    if not raw:
        return {
            "domain": domain,
            "ct_subdomains": [],
            "live_subdomains": [],
            "dead_subdomains": [],
            "total_certs": 0,
            "error": "crt.sh query returned no results"
        }

    enriched = resolve_ct_subdomains(raw, scope)
    live = [e for e in enriched if e.get("live")]
    dead = [e for e in enriched if not e.get("live")]

    # Flag interesting subdomains — dev/staging/admin environments
    interesting_patterns = [
        "dev", "stage", "staging", "test", "beta", "admin", "internal",
        "vpn", "git", "jenkins", "jira", "confluence", "gitlab", "api",
        "old", "backup", "legacy", "preprod", "uat", "qa", "demo"
    ]
    for entry in live:
        sub = entry["subdomain"].lower()
        entry["interesting"] = any(p in sub for p in interesting_patterns)

    return {
        "domain": domain,
        "ct_subdomains": enriched,
        "live_subdomains": live,
        "dead_subdomains": dead,
        "interesting_subdomains": [e for e in live if e.get("interesting")],
        "total_certs": len(raw),
        "total_unique": len(enriched),
        "live_count": len(live)
    }
