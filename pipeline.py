"""
ARES Async Pipeline (v4 — Elite)
Adds:
  - Certificate Transparency subdomain discovery (passive, crt.sh)
  - JavaScript intelligence extraction (endpoints, secrets, cloud refs)
  - EPSS scoring on all CVEs (exploitation probability)
  - Attack graph construction + AI kill chain analysis
  - MITRE ATT&CK technique tagging
"""

import asyncio
import hashlib
import json
import os
import re
import urllib.parse
from datetime import datetime, timezone

from ollama_compat import OllamaClient as Anthropic, DEFAULT_MODEL, extract_first_json_object
from utils.scope_validator import Scope, ScopeValidator
from utils.evidence_model import (
    dedupe_by_key,
    enrich_finding,
    make_asset,
    make_coverage,
    make_evidence,
    merge_subdomains,
    severity_to_priority,
)
from utils.report_generator import generate_report
from utils.capability_profiles import CapabilityProfile, profile_summary, resolve_profile
from utils.roe import evaluate_capability_action, load_roe_policy
from utils.evidence_ledger import build_pipeline_evidence_ledger
from utils.finding_lifecycle import initialize_findings
from utils.config import (
    ASSET_INVENTORY_MAX_HTTP_PROBES,
    ENABLE_NMAP,
    ENABLE_REVERSE_IP,
    ENABLE_RISKY_METHOD_CHECKS,
    PASSIVE_HTTP_ALLOWED,
    RECON_ADDITIONAL_TARGET_MAX,
    PROFILE,
    ROE_POLICY_PATH,
    REDTEAM_MAX_VERIFICATIONS,
    SUBDOMAIN_WORDLIST_MAX,
    SUBDOMAIN_WORDLIST_PATH,
    TLS_ADDITIONAL_TARGET_MAX,
    TLS_TIMEOUT,
    EXTERNAL_LOOKUP_TIMEOUT,
    LAB_MANIFEST_PATH,
)
from tools.network_tools import (
    dns_lookup, whois_lookup, subdomain_enumerate,
    http_probe, check_common_misconfigs, port_scan, fetch_cve_data, redact_org_osint,
    load_subdomain_wordlist, probe_version_disclosure, subdomain_wordlist_source,
)
from tools.cert_transparency import cert_transparency_recon
from tools.external_enrichment import internetdb_lookup, reverse_ip_lookup
from tools.passive_url_discovery import passive_url_discovery
from tools.js_intelligence import js_intelligence
from tools.tls_audit import tls_audit
from tools.redteam_verification import (
    VerificationStatus,
    discover_auth_panels,
    enumerate_api_endpoints,
    test_clickjacking,
    test_host_header_injection,
    test_http_methods,
    test_open_redirect,
    verification_result,
)
from tools.lab_simulation import run_lab_simulations
from tools.nuclei_runner import run_nuclei
from tools.epss_scoring import enrich_cves_with_epss, epss_summary
from tools.attack_graph import build_attack_graph, generate_kill_chains, map_to_mitre

client = Anthropic()

HIGH_INTEREST_SUBDOMAIN_MARKERS = (
    "api", "admin", "auth", "sso", "oauth", "idp", "dev", "staging",
    "stage", "preprod", "uat", "vpn", "portal", "dashboard",
)
HIGH_INTEREST_PATH_MARKERS = (
    "login", "admin", "auth", "sso", "oauth", "graphql", "swagger",
    "openapi", "api-docs",
)
ASSET_PRIORITY_MARKERS = HIGH_INTEREST_SUBDOMAIN_MARKERS
VALID_MODES = {"full", "osint_only", "passive_only", "light_active", "recon_only"}

_SECRET_RAW_KEYS = {"value", "secret", "raw", "raw_secret", "token", "password", "key"}


def _redact_secret_value(value: str) -> str:
    value = str(value or "")
    if not value:
        return ""
    if len(value) <= 8:
        return value[:2] + "..."
    return value[:4] + "..." + value[-4:]


def _safe_secret_type(secret: dict) -> str:
    label = str(secret.get("type") or "API Key")
    lower = label.lower()
    if "aws" in lower and "access" in lower:
        return "AWS Access Key"
    if "github" in lower:
        return "GitHub Token"
    if "stripe" in lower:
        return "Stripe Key"
    if "bearer" in lower:
        return "Bearer Token"
    if "jwt" in lower:
        return "JWT Token"
    if "gitlab" in lower:
        return "GitLab Token"
    if "password" in lower:
        return "Password"
    if "secret" in lower:
        return "Secret"
    return label


def _secret_guidance(secret_type: str) -> tuple[str, str]:
    lower = secret_type.lower()
    if "aws access" in lower:
        return (
            "Access Key ID alone cannot verify AWS access without the paired secret access key. "
            "If this ID was exposed client-side, rotate it and review CloudTrail/IAM usage manually.",
            "HIGH",
        )
    if "github" in lower:
        return (
            "Use only operator-supplied, authorized local metadata checks. Do not call api.github.com "
            "with a discovered token automatically.",
            "HIGH",
        )
    if "stripe" in lower:
        return (
            "Treat secret-looking Stripe keys in client-side code as urgent rotation candidates. "
            "Do not call Stripe APIs with the discovered value automatically.",
            "HIGH",
        )
    return (
        "Rotate the exposed value and perform provider-specific access review through an authorized operator workflow.",
        "MEDIUM",
    )


def build_secret_verification_queue(js_data: dict) -> list[dict]:
    """Build manual-only verification guidance from redacted JS secret findings."""
    queue = []
    seen = set()
    for secret in js_data.get("secrets", []) or []:
        secret_type = _safe_secret_type(secret)
        preview = secret.get("value_preview") or _redact_secret_value(secret.get("value", ""))
        source_url = str(secret.get("source_url") or secret.get("source") or js_data.get("page_url") or js_data.get("url") or "")
        seed = "|".join([
            secret_type,
            str(preview),
            source_url,
            str(secret.get("full_length", "")),
        ])
        secret_id = "secret-" + hashlib.sha256(seed.encode("utf-8", errors="ignore")).hexdigest()[:16]
        if secret_id in seen:
            continue
        seen.add(secret_id)
        recommended_check, default_confidence = _secret_guidance(secret_type)
        confidence = str(secret.get("confidence") or default_confidence).upper()
        if confidence not in {"HIGH", "MEDIUM", "LOW"}:
            confidence = default_confidence
        queue.append({
            "secret_id": secret_id,
            "type": secret_type,
            "value_preview": preview,
            "source_url": source_url,
            "confidence": confidence,
            "manual_verification": True,
            "recommended_safe_check": recommended_check,
            "raw_secret_stored": False,
            "rotation_recommended": True,
        })
    return queue


def _sanitize_js_data(js_data: dict) -> dict:
    """Strip raw credential-looking fields from JS intelligence before emitting or persisting."""
    sanitized = dict(js_data or {})
    safe_secrets = []
    for secret in sanitized.get("secrets", []) or []:
        item = {
            k: v for k, v in dict(secret).items()
            if k not in _SECRET_RAW_KEYS and not k.startswith("raw_")
        }
        if not item.get("value_preview") and secret.get("value"):
            item["value_preview"] = _redact_secret_value(secret.get("value", ""))
        item["raw_secret_stored"] = False
        safe_secrets.append(item)
    sanitized["secrets"] = safe_secrets
    return sanitized


def _host_from_url_or_host(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    parsed = urllib.parse.urlparse(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or raw).strip().lower().rstrip(".")


def _inventory_priority(host: str, url: str = "", source: str = "") -> tuple[int, list[str]]:
    haystack = f"{host} {url}".lower()
    hints = [marker for marker in ASSET_PRIORITY_MARKERS if marker in haystack]
    if hints:
        base = 0
    elif source == "target":
        base = 1
    elif source in {"passive_url", "crawl"}:
        base = 2
    elif source in {"ct", "subdomain"}:
        base = 3
    elif source == "internetdb":
        base = 4
    else:
        base = 5
    return base, [f"priority marker: {hint}" for hint in hints]


def _make_inventory_asset(host: str, url: str, source: str, in_scope: bool,
                          http_probe_data: dict | None = None,
                          tech_stack: list | None = None,
                          cpe_strings: list | None = None,
                          risk_hints: list | None = None,
                          priority: int | None = None) -> dict:
    host = _host_from_url_or_host(host or url)
    url = url or (f"https://{host}" if host else "")
    computed_priority, computed_hints = _inventory_priority(host, url, source)
    probe = http_probe_data or {}
    hints = list(dict.fromkeys((risk_hints or []) + computed_hints))
    tech = list(dict.fromkeys(list(tech_stack or []) + list(probe.get("tech_signals", []) or [])))
    cpes = list(dict.fromkeys(list(cpe_strings or []) + list(probe.get("cpe_strings", []) or [])))
    return {
        "asset_id": "asset-" + hashlib.sha1("|".join([host, url, source]).encode("utf-8", errors="ignore")).hexdigest()[:12],
        "host": host,
        "url": url,
        "source": source,
        "in_scope": bool(in_scope),
        "http_probe": probe,
        "tech_stack": tech,
        "cpe_strings": cpes,
        "risk_hints": hints,
        "priority": computed_priority if priority is None else priority,
        "notable_findings_count": len(hints),
    }


def _merge_inventory_assets(assets: list[dict]) -> list[dict]:
    merged: dict[tuple[str, str], dict] = {}
    source_rank = {"target": 0, "dns": 1, "ct": 2, "subdomain": 3, "internetdb": 4, "passive_url": 5, "crawl": 6, "additional_recon": 7}
    for asset in assets:
        if not asset.get("host") and not asset.get("url"):
            continue
        key = (asset.get("host", ""), asset.get("url", ""))
        current = merged.get(key)
        if current is None:
            merged[key] = dict(asset)
            continue
        current["source"] = min([current.get("source", ""), asset.get("source", "")], key=lambda s: source_rank.get(s, 99))
        current["in_scope"] = current.get("in_scope") or asset.get("in_scope")
        current["priority"] = min(current.get("priority", 9), asset.get("priority", 9))
        current["risk_hints"] = list(dict.fromkeys(current.get("risk_hints", []) + asset.get("risk_hints", [])))
        current["tech_stack"] = list(dict.fromkeys(current.get("tech_stack", []) + asset.get("tech_stack", [])))
        current["cpe_strings"] = list(dict.fromkeys(current.get("cpe_strings", []) + asset.get("cpe_strings", [])))
        if asset.get("http_probe") and not current.get("http_probe"):
            current["http_probe"] = asset.get("http_probe", {})
        current["notable_findings_count"] = len(current.get("risk_hints", []))
    return sorted(merged.values(), key=lambda item: (item.get("priority", 9), item.get("host", ""), item.get("url", "")))


def build_asset_inventory(target: str, dns: dict, subdomains: dict, ct_data: dict, internetdb: dict,
                          passive_urls: dict, js_data: dict, http_data: dict,
                          validator: ScopeValidator | None = None) -> list[dict]:
    """Build scoped per-asset inventory used as OSINT-to-recon feedback."""
    validator = validator or ScopeValidator(Scope(domains=[target]))
    assets = []
    main_url = http_data.get("url") or f"https://{target}"
    assets.append(_make_inventory_asset(
        target,
        main_url,
        "target",
        True,
        http_probe_data=http_data,
        tech_stack=http_data.get("tech_signals", []),
        cpe_strings=http_data.get("cpe_strings", []),
    ))
    if dns.get("resolved_ip"):
        assets.append(_make_inventory_asset(dns["resolved_ip"], "", "dns", True))
    for source, items in (
        ("subdomain", subdomains.get("discovered_subdomains", [])),
        ("ct", ct_data.get("live_subdomains", []) + ct_data.get("interesting_subdomains", [])),
    ):
        for item in items:
            host = item.get("subdomain", "") if isinstance(item, dict) else str(item)
            url = f"https://{host}"
            in_scope, _ = validator.validate(url)
            assets.append(_make_inventory_asset(host, url, source, in_scope))
    for host in internetdb.get("hostnames", []) or []:
        url = f"https://{host}"
        in_scope, _ = validator.validate(url)
        if in_scope:
            assets.append(_make_inventory_asset(host, url, "internetdb", True, cpe_strings=internetdb.get("cpes", [])))
    for url in passive_urls.get("discovered_urls", []) or []:
        in_scope, _ = validator.validate(url)
        assets.append(_make_inventory_asset(_host_from_url_or_host(url), url, "passive_url", in_scope))
    for page in js_data.get("pages_crawled", []) or []:
        url = page.get("url", "") if isinstance(page, dict) else str(page)
        in_scope, _ = validator.validate(url)
        assets.append(_make_inventory_asset(_host_from_url_or_host(url), url, "crawl", in_scope))
    return _merge_inventory_assets(assets)


def select_inventory_http_probe_targets(asset_inventory: list[dict], max_probes: int = ASSET_INVENTORY_MAX_HTTP_PROBES) -> list[dict]:
    candidates = [
        asset for asset in asset_inventory
        if asset.get("in_scope")
        and asset.get("source") in {"subdomain", "ct", "internetdb"}
        and not asset.get("http_probe")
        and asset.get("priority", 9) <= 1
        and asset.get("url")
    ]
    return sorted(candidates, key=lambda item: (item.get("priority", 9), item.get("host", "")))[:max_probes]


def merge_additional_recon_into_inventory(asset_inventory: list[dict], additional_results: dict, validator: ScopeValidator | None = None) -> list[dict]:
    assets = list(asset_inventory or [])
    probes_by_url = {item.get("url"): item for item in additional_results.get("probes", []) or []}
    for target_item in additional_results.get("targets", []) or []:
        url = target_item.get("url", "")
        if not url:
            continue
        in_scope = True
        if validator:
            in_scope, _ = validator.validate(url)
        probe = probes_by_url.get(url, {})
        assets.append(_make_inventory_asset(
            _host_from_url_or_host(url),
            url,
            "additional_recon",
            in_scope,
            http_probe_data=probe,
            tech_stack=probe.get("tech_signals", []),
            cpe_strings=probe.get("cpe_strings", []),
            risk_hints=[target_item.get("reason", "")] if target_item.get("reason") else [],
            priority=target_item.get("priority", 5),
        ))
    return _merge_inventory_assets(assets)


def _base_url_for_target(target: str, osint_data: dict) -> str:
    url = osint_data.get("collection_summary", {}).get("http_url") or f"https://{target}"
    if "://" not in url:
        url = f"https://{url}"
    parsed = urllib.parse.urlparse(url)
    if not parsed.netloc:
        return f"https://{target}"
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))


def _normalize_recon_url(base_url: str, value: str) -> str | None:
    value = (value or "").strip()
    if not value or value.startswith(("#", "javascript:", "mailto:", "tel:")):
        return None
    full = urllib.parse.urljoin(base_url, value)
    parsed = urllib.parse.urlparse(full)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def _recon_url_key(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    return urllib.parse.urlunparse((parsed.scheme.lower(), netloc, path.rstrip("/") or "/", "", parsed.query, ""))


def _path_priority(url: str, source: str, method: str = "GET") -> tuple[int, str]:
    path = urllib.parse.urlparse(url).path.lower()
    query = urllib.parse.urlparse(url).query.lower()
    joined = path + ("?" + query if query else "")
    if "/api/" in joined or joined.startswith("/api") or "graphql" in joined:
        return 0, "API or GraphQL endpoint"
    if source == "form" and method.upper() == "POST":
        return 1, "POST form action URL (GET probe only; form not submitted)"
    if any(marker in joined for marker in ("login", "admin", "auth", "sso", "oauth")):
        return 2, "login/admin/auth surface"
    if any(marker in joined for marker in ("swagger", "openapi", "api-docs", "graphql")):
        return 3, "API documentation or schema surface"
    if source in ("subdomain", "internetdb"):
        return 4, "high-interest subdomain"
    if source == "passive_url":
        return 5, "passive robots/sitemap URL"
    return 6, source


def _is_high_interest_subdomain(hostname: str) -> bool:
    first = (hostname or "").split(".", 1)[0].lower()
    return any(marker == first or first.startswith(marker + "-") or first.startswith(marker) for marker in HIGH_INTEREST_SUBDOMAIN_MARKERS)


def build_additional_recon_targets(
    target: str,
    osint_data: dict,
    max_targets: int = 25,
    validator: ScopeValidator | None = None,
) -> list[dict]:
    """Build capped, GET-safe additional HTTP targets from OSINT application surface."""
    validator = validator or ScopeValidator(Scope(domains=[target, f"*.{target}"]))
    base_url = _base_url_for_target(target, osint_data)
    candidates = []

    def add(raw_url: str, source: str, reason: str, method: str = "GET", priority: int | None = None):
        url = _normalize_recon_url(base_url, raw_url)
        if not url:
            return
        valid, _ = validator.validate(url)
        if not valid:
            return
        effective_priority = priority
        effective_reason = reason
        if effective_priority is None:
            effective_priority, inferred = _path_priority(url, source, method)
            effective_reason = reason or inferred
        candidates.append({
            "url": url,
            "source": source,
            "reason": effective_reason,
            "method": method.upper() if method else "UNKNOWN",
            "priority": effective_priority,
        })

    js_data = osint_data.get("_js_data", {})
    for endpoint in js_data.get("endpoints", []):
        add(endpoint, "js", "", method="GET")
    for form in js_data.get("forms", []):
        add(form.get("action", ""), "form", "form action URL (not submitted)", method=form.get("method", "UNKNOWN"))
    for page in js_data.get("pages_crawled", []):
        add(page.get("url", ""), "crawl", "crawled page", method="GET")
    for url in osint_data.get("_passive_urls", {}).get("discovered_urls", []):
        add(url, "passive_url", "passive robots/sitemap URL", method="GET")

    subdomain_items = list(osint_data.get("subdomains", [])) + list(osint_data.get("_ct_subdomains", []))
    for item in subdomain_items:
        host = item.get("subdomain") if isinstance(item, dict) else str(item)
        if host and _is_high_interest_subdomain(host):
            add(f"https://{host}", "subdomain", "high-interest subdomain", method="GET", priority=4)

    internetdb = osint_data.get("_external_enrichment", {}).get("internetdb", {})
    for host in internetdb.get("hostnames", []):
        if host and _is_high_interest_subdomain(host):
            add(f"https://{host}", "internetdb", "in-scope InternetDB hostname", method="GET", priority=4)

    deduped = []
    seen = set()
    for item in sorted(candidates, key=lambda entry: (entry["priority"], entry["url"])):
        key = _recon_url_key(item["url"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
        if len(deduped) >= max_targets:
            break
    return deduped

def _clean_json(text: str) -> str:
    """Strip <think> blocks, markdown fences, then extract the first JSON object."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = re.sub(r"```(?:json)?\n?", "", text)
    text = re.sub(r"```", "", text)
    return extract_first_json_object(text.strip())


def _grounded_osint_summary(target, resolved_ip, tech_signals, ct_total, js_data, misconfigs, http_data, external_enrichment=None, passive_urls=None):
    external_enrichment = external_enrichment or {}
    internetdb = external_enrichment.get("internetdb", {})
    reverse_ip = external_enrichment.get("reverse_ip", {})
    passive_urls = passive_urls or {}
    parts = []
    if resolved_ip:
        parts.append(f"{target} resolved to {resolved_ip}.")
    else:
        parts.append(f"{target} was analyzed with limited network visibility.")
    parts.append(
        f"Certificate Transparency yielded {ct_total} unique names; "
        f"JavaScript analysis found {len(js_data.get('endpoints', []))} endpoints and {len(js_data.get('secrets', []))} secrets."
    )
    if tech_signals:
        parts.append(f"Observed technologies: {', '.join(tech_signals[:5])}.")
    else:
        parts.append("No reliable technology fingerprints were captured.")
    if http_data.get("partial"):
        parts.append("HTTP probing was partial after a timeout, so stack identification may be incomplete.")
    elif http_data.get("error"):
        parts.append("HTTP probing did not return usable response data.")
    if misconfigs.get("budget_exhausted"):
        parts.append(
            f"Misconfiguration checks reached the time budget after {misconfigs.get('paths_checked', 0)}/"
            f"{misconfigs.get('paths_total', 0)} paths."
        )
    if internetdb.get("status") == "success":
        parts.append(
            "InternetDB passive enrichment observed "
            f"{len(internetdb.get('ports', []))} ports, "
            f"{len(internetdb.get('hostnames', []))} hostnames, "
            f"{len(internetdb.get('vulns', []))} vulnerability references, and "
            f"{len(internetdb.get('cpes', []))} CPEs."
        )
    elif internetdb.get("status") in ("no_data", "failed"):
        parts.append(f"InternetDB enrichment status: {internetdb.get('status')}.")
    if reverse_ip:
        parts.append(
            f"Reverse-IP enrichment status: {reverse_ip.get('status', 'skipped')} "
            f"with {len(reverse_ip.get('hostnames', []))} ownership-unverified hostnames."
        )
    if passive_urls:
        security_status = passive_urls.get("security_txt", {}).get("status_code", 0)
        parts.append(
            "Passive URL discovery found "
            f"{len(passive_urls.get('discovered_urls', []))} in-scope URLs, "
            f"{len(passive_urls.get('suggested_dorks', []))} suggested manual dorks, and "
            f"security.txt status {security_status or 'not found'}."
        )
    return " ".join(parts)


def _dedupe_cves(cves: list[dict]) -> list[dict]:
    deduped = []
    seen = set()
    for cve in cves:
        key = (cve.get("id"), cve.get("published"), cve.get("description"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(cve)
    return deduped


def _ground_osint_report(target, dns, whois, subdomains, http, misconfigs, ct_data, js_data, report, external_enrichment=None, passive_urls=None, secret_verification_queue=None):
    external_enrichment = external_enrichment or {}
    internetdb = external_enrichment.get("internetdb", {})
    reverse_ip = external_enrichment.get("reverse_ip", {})
    passive_urls = passive_urls or {}
    secret_verification_queue = secret_verification_queue if secret_verification_queue is not None else build_secret_verification_queue(js_data)
    tech_signals = list(http.get("tech_signals", []))
    tech_inventory = list(http.get("tech_details", []))
    discovered_subdomains = merge_subdomains(
        subdomains.get("discovered_subdomains", []),
        ct_data.get("live_subdomains", []),
        ct_data.get("interesting_subdomains", []),
    )
    org_osint = whois.get("org_osint") or {
        "organization": whois.get("fields", {}).get("Registrant Organization", ""),
        "registrar": whois.get("fields", {}).get("Registrar", ""),
        "emails": [],
        "abuse_emails": [],
        "source": "whois",
    }
    public_org_osint = redact_org_osint(org_osint)
    org = org_osint.get("organization") or None
    cdn = "Cloudflare" if any("cloudflare" in str(t).lower() for t in tech_signals) else None
    coverage_gaps = []
    if http.get("partial"):
        coverage_gaps.append("http_probe_partial")
    elif http.get("error"):
        coverage_gaps.append("http_probe_failed")
    if misconfigs.get("budget_exhausted"):
        coverage_gaps.append("misconfig_budget_exhausted")
    if js_data.get("error"):
        coverage_gaps.append("js_collection_failed")
    risk_score = (
        len(misconfigs.get("findings", [])) * 2
        + len(js_data.get("secrets", [])) * 3
        + len(ct_data.get("interesting_subdomains", []))
        + (2 if tech_signals else 0)
        + min(2, len(misconfigs.get("restricted_findings", [])))
    )
    if coverage_gaps:
        risk_score = max(risk_score, min(6, 3 + len(coverage_gaps)))
    risk_score = min(10, max(1, risk_score))
    assets = [
        make_asset("domain", target, confidence="HIGH", in_scope=True),
    ]
    if dns.get("resolved_ip"):
        assets.append(make_asset("ip", dns["resolved_ip"], confidence="HIGH", source="dns_lookup"))
    assets.extend(
        make_asset("subdomain", item["subdomain"], value=item.get("ip", ""), confidence="MEDIUM", source="ct_or_dns")
        for item in discovered_subdomains
    )
    assets.extend(
        make_asset(
            "technology",
            tech.get("name", ""),
            value=tech.get("version", ""),
            confidence="HIGH" if tech.get("version") else "MEDIUM",
            cpe=tech.get("cpe", ""),
            vendor=tech.get("cpe", "").split(":")[0] if tech.get("cpe") else "",
            product=tech.get("cpe", "").split(":")[1] if tech.get("cpe") and ":" in tech.get("cpe", "") else "",
        )
        for tech in tech_inventory
        if tech.get("name")
    )
    if internetdb.get("status") == "success":
        for hostname in internetdb.get("hostnames", []):
            assets.append(make_asset("hostname", hostname, confidence="MEDIUM", source="shodan_internetdb"))
        for port in internetdb.get("ports", []):
            assets.append(make_asset("service", f"{internetdb.get('ip', '')}:{port}", confidence="MEDIUM", source="shodan_internetdb"))
    evidence_log = [
        make_evidence("dns_lookup", "resolution", f"{target} resolved to {dns['resolved_ip']}", confidence="HIGH")
        for _ in [0] if dns.get("resolved_ip")
    ]
    if ct_data.get("total_unique", 0):
        evidence_log.append(
            make_evidence(
                "cert_transparency",
                "subdomain_discovery",
                f"Certificate Transparency returned {ct_data.get('total_unique', 0)} unique names",
                confidence="MEDIUM",
                interesting=ct_data.get("interesting_subdomains", []),
            )
        )
    if tech_signals:
        evidence_log.append(
            make_evidence(
                "http_probe",
                "technology_fingerprint",
                f"Observed technologies: {', '.join(tech_signals[:5])}",
                confidence="HIGH" if http.get("status_code") else "MEDIUM",
                url=http.get("url", target),
                status_code=http.get("status_code"),
            )
        )
    if misconfigs.get("findings"):
        evidence_log.append(
            make_evidence(
                "check_common_misconfigs",
                "web_exposure",
                f"Observed {len(misconfigs.get('findings', []))} exposed paths",
                confidence="HIGH",
                findings=misconfigs.get("findings", []),
            )
        )
    if js_data.get("secrets") or js_data.get("endpoints"):
        evidence_log.append(
            make_evidence(
                "js_intelligence",
                "frontend_discovery",
                f"JS analysis found {len(js_data.get('endpoints', []))} endpoints and {len(js_data.get('secrets', []))} secrets",
                confidence="HIGH",
                page_url=js_data.get("page_url", target),
            )
        )
    if internetdb:
        evidence_log.append(
            make_evidence(
                "shodan_internetdb",
                "external_enrichment",
                f"InternetDB status {internetdb.get('status', 'unknown')} for {internetdb.get('ip', dns.get('resolved_ip', ''))}",
                confidence="MEDIUM",
                ports=internetdb.get("ports", []),
                hostnames=internetdb.get("hostnames", []),
                vulns=internetdb.get("vulns", []),
                cpes=internetdb.get("cpes", []),
                error=internetdb.get("error", ""),
            )
        )
    if reverse_ip:
        evidence_log.append(
            make_evidence(
                "hackertarget_reverse_ip",
                "reverse_ip_enrichment",
                f"Reverse-IP status {reverse_ip.get('status', 'unknown')} for {reverse_ip.get('query', '')}",
                confidence="LOW",
                hostnames=reverse_ip.get("hostnames", []),
                ownership_unverified=True,
                error=reverse_ip.get("error", ""),
            )
        )
    if passive_urls:
        evidence_log.append(
            make_evidence(
                "passive_url_discovery",
                "passive_url_inventory",
                f"Passive URL discovery returned {len(passive_urls.get('discovered_urls', []))} in-scope URLs",
                confidence="MEDIUM",
                robots_status=passive_urls.get("robots", {}).get("status_code", 0),
                sitemap_urls=len(passive_urls.get("sitemaps", {}).get("urls", [])),
                security_txt_status=passive_urls.get("security_txt", {}).get("status_code", 0),
                suggested_dorks_count=len(passive_urls.get("suggested_dorks", [])),
            )
        )
    coverage = [
        make_coverage("osint", "dns_lookup", "success" if dns.get("resolved_ip") else "partial", resolved_ip=dns.get("resolved_ip", "")),
        make_coverage("osint", "whois_lookup", "success" if whois.get("fields") else "partial"),
        make_coverage("osint", "subdomain_enumerate", "success", discovered=len(subdomains.get("discovered_subdomains", []))),
        make_coverage("osint", "cert_transparency_recon", "success" if ct_data else "partial", discovered=ct_data.get("total_unique", 0)),
        make_coverage(
            "osint",
            "http_probe",
            "partial" if http.get("partial") else "failed" if http.get("error") and not http.get("status_code") else "success",
            details=http.get("error", ""),
            status_code=http.get("status_code"),
        ),
        make_coverage(
            "osint",
            "js_intelligence",
            "failed" if js_data.get("error") else "success",
            details=js_data.get("error", ""),
            scripts_analyzed=js_data.get("script_count", 0),
        ),
        make_coverage(
            "osint",
            "check_common_misconfigs",
            "partial" if misconfigs.get("budget_exhausted") else "success",
            details="time budget exhausted" if misconfigs.get("budget_exhausted") else "",
            findings=len(misconfigs.get("findings", [])),
        ),
        make_coverage(
            "osint",
            "shodan_internetdb",
            internetdb.get("status", "skipped") if internetdb else "skipped",
            details=internetdb.get("error", "") if internetdb else "",
            ports=len(internetdb.get("ports", [])) if internetdb else 0,
            hostnames=len(internetdb.get("hostnames", [])) if internetdb else 0,
            vulns=len(internetdb.get("vulns", [])) if internetdb else 0,
            cpes=len(internetdb.get("cpes", [])) if internetdb else 0,
        ),
        make_coverage(
            "osint",
            "hackertarget_reverse_ip",
            reverse_ip.get("status", "skipped") if reverse_ip else "skipped",
            details=reverse_ip.get("error", "") if reverse_ip else "",
            hostnames=len(reverse_ip.get("hostnames", [])) if reverse_ip else 0,
            ownership_unverified=True,
        ),
        make_coverage(
            "osint",
            "passive_url_discovery",
            "success" if passive_urls else "skipped",
            discovered=len(passive_urls.get("discovered_urls", [])) if passive_urls else 0,
            suggested_dorks=len(passive_urls.get("suggested_dorks", [])) if passive_urls else 0,
        ),
    ]
    return {
        "summary": _grounded_osint_summary(
            target,
            dns.get("resolved_ip", ""),
            tech_signals,
            ct_data.get("total_unique", 0),
            js_data,
            misconfigs,
            http,
            external_enrichment,
            passive_urls,
        ),
        "infrastructure": {"hosting": "Unknown", "cdn": cdn, "org": org},
        "subdomains": discovered_subdomains,
        "technology_stack": tech_signals,
        "open_ports": [],
        "risk_score": risk_score,
        "misconfig_count": len(misconfigs.get("findings", [])),
        "attack_surface_notes": (
            f"JS endpoints: {len(js_data.get('endpoints', []))}; "
            f"JS secrets: {len(js_data.get('secrets', []))}; "
            f"CT interesting subdomains: {len(ct_data.get('interesting_subdomains', []))}; "
            f"misconfig findings: {len(misconfigs.get('findings', []))}; "
            f"restricted paths: {len(misconfigs.get('restricted_findings', []))}; "
            f"InternetDB ports: {len(internetdb.get('ports', []))}; "
            f"InternetDB hostnames: {len(internetdb.get('hostnames', []))}; "
            f"InternetDB vulns: {len(internetdb.get('vulns', []))}; "
            f"InternetDB CPEs: {len(internetdb.get('cpes', []))}; "
            f"reverse-IP unverified hostnames: {len(reverse_ip.get('hostnames', []))}; "
            f"passive URLs: {len(passive_urls.get('discovered_urls', []))}; "
            f"suggested dorks: {len(passive_urls.get('suggested_dorks', []))}; "
            f"page source: {js_data.get('page_url', http.get('url', target))}."
        ),
        "coverage_gaps": coverage_gaps,
        "coverage": coverage,
        "assets": dedupe_by_key(assets, ("asset_type", "name", "value")),
        "evidence_log": evidence_log,
        "technology_inventory": tech_inventory,
        "passive_url_discovery": passive_urls,
        "secret_verification_queue": secret_verification_queue,
        "org_osint": public_org_osint,
        "collection_summary": {
            "http_status": http.get("status_code"),
            "http_url": http.get("url", target),
            "page_url": js_data.get("page_url", http.get("url", target)),
            "ct_total_unique": ct_data.get("total_unique", 0),
            "ct_interesting": len(ct_data.get("interesting_subdomains", [])),
            "misconfig_budget_exhausted": bool(misconfigs.get("budget_exhausted")),
            "internetdb_status": internetdb.get("status"),
            "internetdb_ports": internetdb.get("ports", []),
            "internetdb_hostnames": internetdb.get("hostnames", []),
            "internetdb_vulns": internetdb.get("vulns", []),
            "internetdb_cpes": internetdb.get("cpes", []),
            "reverse_ip_status": reverse_ip.get("status"),
            "reverse_ip_hostnames": reverse_ip.get("hostnames", []),
            "reverse_ip_ownership_unverified": reverse_ip.get("ownership_unverified", True) if reverse_ip else True,
            "passive_url_count": len(passive_urls.get("discovered_urls", [])),
            "suggested_dorks_count": len(passive_urls.get("suggested_dorks", [])),
        },
    }


def _ground_vuln_report(target, osint, ports, cves, report):
    critical_findings = []
    high_findings = []
    medium_findings = []
    evidence_log = []
    service_inventory = []

    for service in ports.get("service_inventory", []):
        name = (
            f"{service.get('port')}/{service.get('protocol', 'tcp')} "
            f"{service.get('service', '')} {service.get('product', '')} {service.get('version', '')}"
        ).strip()
        service_inventory.append(
            make_asset(
                "service",
                name,
                confidence=service.get("confidence", "MEDIUM"),
                source="port_scan",
                port=service.get("port"),
                protocol=service.get("protocol"),
                product=service.get("product"),
                version=service.get("version"),
                cpes=service.get("candidate_cpes", []),
            )
        )
    if not service_inventory:
        for port_line in ports.get("open_ports", []):
            service_inventory.append(
                make_asset("service", port_line, confidence="HIGH", source="port_scan")
            )
    if service_inventory:
        evidence_log.append(
            make_evidence(
                "port_scan",
                "service_inventory",
                f"Observed {len(service_inventory)} open services",
                confidence="HIGH",
                open_ports=ports.get("open_ports", []),
                structured_services=ports.get("service_inventory", []),
            )
        )

    secret_queue = osint.get("_secret_verification_queue") or osint.get("secret_verification_queue") or build_secret_verification_queue(osint.get("_js_data", {}))
    for secret in secret_queue:
        finding = enrich_finding({
            "title": f"Hardcoded {secret['type']} in JavaScript",
            "description": (
                f"Manual verification queued for {secret['type']} from client-side JavaScript. "
                f"Preview: {secret.get('value_preview', '')}. {secret.get('recommended_safe_check', '')}"
            ),
            "cvss_score": 9.0 if secret.get("confidence") == "HIGH" and secret.get("type") in {"AWS Access Key", "Stripe Key"} else 7.5,
            "affected": secret.get("source_url") or "Client-side JavaScript",
            "secret_id": secret.get("secret_id"),
            "raw_secret_stored": False,
            "manual_verification": True,
        }, severity="CRITICAL" if secret.get("type") in {"AWS Access Key", "Stripe Key"} and secret.get("confidence") == "HIGH" else "HIGH",
           evidence_refs=["js_intelligence"], confidence="HIGH", exploitability="MEDIUM", business_impact="HIGH")
        if finding["cvss_score"] >= 9.0:
            critical_findings.append(finding)
        else:
            high_findings.append(finding)

    for finding in osint.get("_misconfigs", []):
        entry = enrich_finding({
            "title": f"Exposed path {finding.get('path', '')}",
            "description": f"Observed HTTP status {finding.get('status', 'unknown')}",
            "cvss_score": 7.5 if finding.get("severity") == "HIGH" else 5.0,
            "affected": finding.get("path", ""),
        }, severity="HIGH" if finding.get("severity") == "HIGH" else "MEDIUM",
           evidence_refs=["check_common_misconfigs"], confidence="HIGH", exploitability="LOW", business_impact="MEDIUM")
        if finding.get("severity") == "HIGH":
            high_findings.append(entry)
        else:
            medium_findings.append(entry)

    for cve in cves:
        entry = enrich_finding({
            "title": cve.get("id", "CVE"),
            "description": cve.get("description", ""),
            "cvss_score": cve.get("cvss_score"),
            "affected": (osint.get("technology_stack") or ["Unknown"])[0] if osint.get("technology_stack") else "Unknown",
            "epss": cve.get("epss"),
        }, severity="CRITICAL" if (cve.get("cvss_score") or 0) >= 9.0 else "HIGH" if (cve.get("cvss_score") or 0) >= 7.0 else "MEDIUM",
           evidence_refs=["fetch_cve_data"], confidence="HIGH" if cve.get("cvss_score") else "MEDIUM",
           exploitability="HIGH" if (cve.get("epss") or 0) >= 0.1 else "MEDIUM", business_impact="HIGH")
        score = cve.get("cvss_score") or 0
        if score >= 9.0:
            critical_findings.append(entry)
        elif score >= 7.0:
            high_findings.append(entry)
        elif score >= 4.0:
            medium_findings.append(entry)

    missing_headers = osint.get("_missing_security_headers", [])
    if missing_headers:
        medium_findings.append(enrich_finding({
            "title": "Missing Security Headers",
            "description": "Missing headers: " + ", ".join(missing_headers),
            "cvss_score": 5.0,
            "affected": "Web application responses",
        }, severity="MEDIUM", evidence_refs=["http_probe"], confidence="HIGH", exploitability="LOW", business_impact="MEDIUM"))

    version_disclosure = osint.get("_version_disclosure", {})
    for finding in version_disclosure.get("findings", []):
        severity = finding.get("severity", "LOW")
        score = {
            "CRITICAL": 9.2,
            "HIGH": 8.0,
            "MEDIUM": 5.5,
            "LOW": 3.1,
        }.get(severity, 3.1)
        entry = enrich_finding({
            "title": finding.get("title", "Version Disclosure"),
            "description": finding.get("description", ""),
            "cvss_score": score,
            "affected": finding.get("url", finding.get("path", "")),
            "evidence_preview": finding.get("evidence_preview", ""),
        }, severity=severity, evidence_refs=finding.get("evidence_refs", ["probe_version_disclosure"]),
           confidence="HIGH", exploitability="LOW", business_impact="MEDIUM")
        if severity == "CRITICAL":
            critical_findings.append(entry)
        elif severity == "HIGH":
            high_findings.append(entry)
        else:
            medium_findings.append(entry)

    tls_data = osint.get("_tls_audit", {})
    for finding in tls_data.get("findings", []):
        severity = finding.get("severity", "MEDIUM")
        score = {"HIGH": 7.0, "MEDIUM": 5.0, "LOW": 3.0}.get(severity, 5.0)
        entry = enrich_finding({
            "title": finding.get("title", "TLS finding"),
            "description": finding.get("description", ""),
            "cvss_score": score,
            "affected": f"{tls_data.get('target', target)}:{tls_data.get('port', 443)}",
            "tls_evidence": finding.get("evidence", {}),
        }, severity=severity, evidence_refs=finding.get("evidence_refs", ["tls_audit"]),
           confidence="HIGH", exploitability="LOW", business_impact="MEDIUM")
        if severity == "HIGH":
            high_findings.append(entry)
        else:
            medium_findings.append(entry)

    attack_vectors = []
    if ports.get("open_ports"):
        attack_vectors.append("Exposed network services")
    if critical_findings or high_findings:
        attack_vectors.append("Public-facing application weaknesses")
    if secret_queue:
        attack_vectors.append("Client-side secret exposure")
    if version_disclosure.get("findings"):
        attack_vectors.append("Exposed framework or version disclosure paths")
    if tls_data.get("findings"):
        attack_vectors.append("Weak TLS posture")
    coverage_gaps = list(osint.get("coverage_gaps", []))
    if ports.get("error"):
        coverage_gaps.append("port_scan_failed")
    if cves:
        evidence_log.append(
            make_evidence(
                "fetch_cve_data",
                "vulnerability_enrichment",
                f"Matched {len(cves)} CVEs to observed technologies",
                confidence="MEDIUM" if any(not c.get("cvss_score") for c in cves) else "HIGH",
                cve_ids=[c.get("id") for c in cves],
            )
        )
    additional_targets = osint.get("_additional_targets", {})
    if additional_targets.get("coverage", {}).get("targets_total", 0):
        evidence_log.append(
            make_evidence(
                "additional_recon_targets",
                "expanded_http_surface",
                f"Probed {additional_targets.get('coverage', {}).get('probed', 0)} additional HTTP targets from OSINT",
                confidence="MEDIUM",
                coverage=additional_targets.get("coverage", {}),
            )
        )
    if tls_data.get("coverage"):
        evidence_log.append(
            make_evidence(
                "tls_audit",
                "tls_posture",
                f"TLS audit for {tls_data.get('target', target)} produced {len(tls_data.get('findings', []))} findings",
                confidence="MEDIUM",
                coverage=tls_data.get("coverage", {}),
                protocols=tls_data.get("protocols", {}),
            )
        )
    if version_disclosure.get("findings") or version_disclosure.get("coverage"):
        evidence_log.append(
            make_evidence(
                "probe_version_disclosure",
                "version_disclosure",
                f"Checked {version_disclosure.get('coverage', {}).get('paths_total', 0)} framework/version paths",
                confidence="MEDIUM",
                coverage=version_disclosure.get("coverage", {}),
                findings=len(version_disclosure.get("findings", [])),
            )
        )

    if critical_findings or high_findings or medium_findings:
        scan_summary = (
            f"Grounded assessment for {target}: "
            f"{len(critical_findings)} critical, {len(high_findings)} high, {len(medium_findings)} medium findings; "
            f"{len(cves)} CVE matches from observed components."
        )
    else:
        scan_summary = (
            f"No grounded vulnerabilities were derived from the collected evidence for {target}. "
            "This reflects current tool output and may still be incomplete if probing or scanning timed out."
        )
    if coverage_gaps:
        scan_summary += " Coverage gaps: " + ", ".join(coverage_gaps) + "."

    prioritized_findings = sorted(
        critical_findings + high_findings + medium_findings,
        key=lambda item: (
            {"P1": 0, "P2": 1, "P3": 2, "P4": 3}.get(item.get("priority", "P4"), 9),
            -(item.get("cvss_score") or 0),
        ),
    )

    return {
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "medium_findings": medium_findings,
        "attack_vectors": attack_vectors,
        "scan_summary": scan_summary,
        "coverage_gaps": coverage_gaps,
        "service_inventory": service_inventory,
        "evidence_log": evidence_log,
        "prioritized_findings": prioritized_findings,
    }


def _ground_redteam_report(target, vulns, test_results, kill_chain_data, report):
    cve_matches = vulns.get("cve_matches", [])
    all_findings = vulns.get("critical_findings", []) + vulns.get("high_findings", []) + vulns.get("medium_findings", [])
    confirmed = list((report or {}).get("confirmed_vulnerabilities", []))
    pocs = list((report or {}).get("proof_of_concepts", []))
    kill_chains = list(kill_chain_data.get("kill_chains", []))

    coverage_gaps = list(vulns.get("coverage_gaps", []))
    if vulns.get("critical_findings"):
        overall_risk = "CRITICAL"
    elif vulns.get("high_findings"):
        overall_risk = "HIGH"
    elif vulns.get("medium_findings"):
        overall_risk = "MEDIUM"
    elif coverage_gaps:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    recommendations = []
    for cve in cve_matches[:5]:
        if cve.get("id"):
            recommendations.append({
                "priority": severity_to_priority("CRITICAL" if (cve.get("cvss_score") or 0) >= 9.0 else "HIGH", cve.get("cvss_score"), cve.get("epss")),
                "recommendation": f"Patch {cve['id']} on affected public-facing components.",
            })
    for finding in vulns.get("critical_findings", []) + vulns.get("high_findings", []):
        title = finding.get("title", "").lower()
        if "hardcoded" in title and "javascript" in title:
            recommendations.append({"priority": "P1", "recommendation": "Rotate exposed client-side secrets and remove them from shipped JavaScript."})
        elif "exposed path" in title:
            recommendations.append({"priority": "P2", "recommendation": f"Restrict access to {finding.get('affected', 'sensitive paths')} and remove publicly exposed files."})
    for finding in vulns.get("medium_findings", []):
        if "missing security headers" in finding.get("title", "").lower():
            recommendations.append({"priority": "P3", "recommendation": finding.get("description", "Implement missing security headers.")})
    if not recommendations:
        recommendations.append({"priority": "P3", "recommendation": "Repeat validation for slow or filtered endpoints and review manual testing coverage before treating the target as low risk."})
    elif coverage_gaps:
        recommendations.append({"priority": "P3", "recommendation": "Scan coverage was incomplete; repeat validation for timed-out or partially scanned surfaces before treating the target as low risk."})

    deduped = []
    seen = set()
    for rec in recommendations:
        key = (rec.get("priority"), rec.get("recommendation"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(rec)

    finding_by_title = {f.get("title", ""): f for f in all_findings}
    for test in test_results:
        result = test.get("result", {})
        test_name = test.get("test", "")
        finding_name = test.get("finding", test_name)
        finding = finding_by_title.get(finding_name, {})
        score = finding.get("cvss_score", 0) or 0
        if score >= 9.0:
            severity = "CRITICAL"
        elif score >= 7.0:
            severity = "HIGH"
        elif score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        if test_name == "exposed_path" and result.get("confirmed"):
            confirmed.append({
                "name": finding_name or f"Exposed path {result.get('path', '')}",
                "severity": severity,
                "evidence": f"{result.get('url', result.get('path', 'Path'))} returned HTTP {result.get('status_code')}.",
                "exploitable": False,
            })
            pocs.append({
                "name": f"Path validation for {result.get('path', finding.get('affected', 'path'))}",
                "payload": result.get("url", ""),
                "result": f"Observed HTTP {result.get('status_code')} while verifying the exposed path.",
            })
        elif test_name == "missing_security_headers" and result.get("missing_headers_confirmed"):
            missing = ", ".join(result.get("missing_headers_confirmed", []))
            confirmed.append({
                "name": finding_name or "Missing Security Headers",
                "severity": severity,
                "evidence": f"Confirmed missing headers: {missing}.",
                "exploitable": False,
            })
            pocs.append({
                "name": "Header verification",
                "payload": result.get("url", ""),
                "result": f"Response was missing: {missing}.",
            })
        elif test_name == "cors" and result.get("misconfigured"):
            confirmed.append({
                "name": finding_name or "CORS misconfiguration",
                "severity": severity,
                "evidence": f"Access-Control-Allow-Origin reflected as {result.get('acao')!r}.",
                "exploitable": False,
            })
        elif test_name == "auth_panel_discovery" and result.get("accessible_panels"):
            panels = ", ".join(result.get("accessible_panels", []))
            pocs.append({
                "name": "Admin panel discovery",
                "payload": panels,
                "result": "Accessible admin/login paths were discovered and require manual credential verification.",
            })
        elif test_name == "open_redirect" and result.get("confirmed"):
            confirmed.append({
                "name": finding_name or "Open redirect",
                "severity": severity,
                "evidence": f"Location reflected marker host: {result.get('location', '')}.",
                "exploitable": False,
            })
        elif test_name == "http_methods" and result.get("findings"):
            for method_finding in result.get("findings", []):
                pocs.append({
                    "name": method_finding.get("type", "HTTP method finding"),
                    "payload": json.dumps(result.get("methods", {}))[:200],
                    "result": "Non-destructive HTTP method probe returned reviewable evidence.",
                })
        elif test_name == "clickjacking" and result.get("confirmed"):
            confirmed.append({
                "name": finding_name or "Clickjacking exposure",
                "severity": severity,
                "evidence": "X-Frame-Options and CSP frame-ancestors were absent.",
                "exploitable": False,
            })
        elif test_name == "host_header_injection" and result.get("reflected"):
            pocs.append({
                "name": "Host header reflection",
                "payload": "Host: evil.example.invalid",
                "result": "Host marker was reflected; manual verification required." if result.get("manual_verification_needed") else "Host marker reflected in redirect Location.",
            })
        elif test_name == "api_endpoint_discovery" and result.get("discovered"):
            pocs.append({
                "name": "API endpoint discovery",
                "payload": ", ".join(item.get("path", "") for item in result.get("discovered", [])[:5]),
                "result": f"{len(result.get('discovered', []))} API endpoints returned 200/401/403.",
            })

    unique_confirmed = []
    seen_confirmed = set()
    for item in confirmed:
        key = (item.get("name"), item.get("evidence"))
        if key in seen_confirmed:
            continue
        seen_confirmed.add(key)
        unique_confirmed.append(item)

    unique_pocs = []
    seen_pocs = set()
    for item in pocs:
        key = (item.get("name"), item.get("payload"), item.get("result"))
        if key in seen_pocs:
            continue
        seen_pocs.add(key)
        unique_pocs.append(item)

    return {
        "confirmed_vulnerabilities": unique_confirmed,
        "kill_chains": kill_chains,
        "proof_of_concepts": unique_pocs,
        "verification_results": test_results,
        "overall_risk": overall_risk,
        "engagement_summary": (
            f"Grounded red team summary for {target}: "
            f"{len(unique_confirmed)} confirmed vulnerabilities, {len(all_findings)} evidence-backed findings, "
            f"{len(kill_chains)} kill chains, and {len(test_results)} verification actions."
            + (f" Coverage gaps remain: {', '.join(coverage_gaps)}." if coverage_gaps else "")
        ),
        "recommendations": deduped[:6],
        "validation_summary": {
            "tests_executed": len(test_results),
            "confirmed_count": len(unique_confirmed),
            "status_counts": {
                status.value: sum(
                    1 for item in test_results
                    if item.get("result", {}).get("status") == status.value
                )
                for status in VerificationStatus
            },
            "coverage_gaps": coverage_gaps,
        },
    }


class ARESPipeline:
    def __init__(
        self,
        target,
        scope,
        mode,
        session,
        log_fn,
        phase_fn,
        emit_fn,
        profile=None,
        roe_policy_path="",
    ):
        self.target = target.strip()
        self.scope = scope
        self.mode = mode.strip().lower()
        if self.mode not in VALID_MODES:
            raise ValueError(f"Invalid ARES mode: {self.mode}")
        self.profile = resolve_profile(profile or PROFILE, legacy_mode=self.mode)
        self.roe_policy_path = (roe_policy_path or ROE_POLICY_PATH or "").strip()
        self.roe = load_roe_policy(self.roe_policy_path)
        self.authorization_gaps = []
        self.audit_events = []
        self.session = session
        self.log = log_fn
        self.phase = phase_fn
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.tools_executed = []

        def tracked_emit(event_type: str, data: dict):
            if event_type == "tool_result":
                tool_name = data.get("tool")
                if tool_name and tool_name not in self.tools_executed:
                    self.tools_executed.append(tool_name)
            emit_fn(event_type, data)

        self.emit = tracked_emit
        self.validator = ScopeValidator(scope)

    def aborted(self):
        return self.session.get("abort", False)

    def authorize_action(self, action: str, target: str = "", method: str = "GET", path: str = "") -> dict:
        decision = evaluate_capability_action(
            {"name": action, "target": target or self.target, "method": method, "path": path},
            self.profile,
            self.roe,
            self.validator,
        )
        event = {
            "action": action,
            "target": target or self.target,
            "method": method.upper(),
            "path": path,
            **decision,
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }
        self.audit_events.append(event)
        if not decision["allowed"]:
            gap = f"capability_blocked:{action}:{decision['matched_rule']}"
            if gap not in self.authorization_gaps:
                self.authorization_gaps.append(gap)
            self.log("WARN", f"Capability blocked [{self.profile.value}] {action}: {decision['reason']}", "orange")
            self.emit("capability_decision", event)
        return decision

    async def run(self) -> dict:
        osint_data, recon_data, redteam_data = {}, {}, {}

        if self.profile == CapabilityProfile.PASSIVE:
            self.mode = "passive_only"

        if self.mode == "recon_only":
            osint_data = await self._build_recon_only_context()
            self.phase("recon", "active", "Hunting CVEs & misconfigs...")
            recon_data = await self._run_recon(osint_data)
            self.emit("results_update", {"phase": "recon", "data": recon_data})
            self.phase("recon", "done", f"{len(recon_data.get('critical_findings', []))} critical, {len(recon_data.get('high_findings', []))} high")
            return self._finalize(osint_data, recon_data, {})

        # ── Phase 1: OSINT ────────────────────────────────────────────────────
        self.phase("osint", "active", "Gathering intelligence...")
        osint_data = await self._run_osint()
        self.emit("results_update", {"phase": "osint", "data": osint_data})
        sub_count = len(osint_data.get("subdomains", [])) + len(osint_data.get("_ct_subdomains", []))
        self.phase("osint", "done", f"{sub_count} subdomains, {osint_data.get('_js_endpoints_count', 0)} JS endpoints")

        if self.aborted() or self.mode in {"osint_only", "passive_only"}:
            return self._finalize(osint_data, {}, {})

        # ── Phase 2: Recon ────────────────────────────────────────────────────
        self.phase("recon", "active", "Hunting CVEs & misconfigs...")
        recon_data = await self._run_recon(osint_data)
        self.emit("results_update", {"phase": "recon", "data": recon_data})
        crit = len(recon_data.get("critical_findings", []))
        high = len(recon_data.get("high_findings", []))
        p1 = recon_data.get("_epss_summary", {}).get("p1_immediate", 0)
        self.phase("recon", "done", f"{crit} critical, {high} high, {p1} P1-immediate CVEs")

        if self.aborted() or self.mode in {"recon_only", "light_active"}:
            return self._finalize(osint_data, recon_data, {})

        # ── Phase 3: Red Team ─────────────────────────────────────────────────
        redteam_decision = self.authorize_action("advanced_verification", self.target)
        if not redteam_decision["allowed"]:
            recon_data.setdefault("coverage_gaps", []).extend(self.authorization_gaps)
            return self._finalize(osint_data, recon_data, {})
        self.phase("redteam", "active", "Testing + building kill chains...")
        redteam_data = await self._run_redteam(recon_data, osint_data)
        self.emit("results_update", {"phase": "redteam", "data": redteam_data})
        chain_risk = redteam_data.get("overall_risk", "?")
        chains = len(redteam_data.get("kill_chains", []))
        self.phase("redteam", "done", f"Risk: {chain_risk}, {chains} kill chains mapped")

        return self._finalize(osint_data, recon_data, redteam_data)

    def _finalize(self, osint, recon, redteam):
        self.log("ORCH", "Generating assessment report...", "blue")
        manifest = self._run_manifest(osint, recon, redteam)
        run_id = str(self.session.get("id") or self.session.get("session_id") or hashlib.sha256(
            f"{self.target}|{self.started_at}".encode()
        ).hexdigest()[:16])
        evidence_ledger = build_pipeline_evidence_ledger(
            run_id,
            self.profile.value,
            self.target,
            osint,
            recon,
            redteam,
        )
        redteam["evidence_ledger"] = evidence_ledger
        initialize_findings({"recon": recon})
        manifest["run_id"] = run_id
        manifest["evidence_record_count"] = len(evidence_ledger)
        osint["run_manifest"] = manifest
        recon["run_manifest"] = manifest
        redteam["run_manifest"] = manifest
        try:
            reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
            report_path = generate_report(
                target=self.target,
                osint_report=osint,
                vuln_report=recon,
                redteam_report=redteam,
                output_dir=reports_dir,
                run_manifest=manifest,
            )
            self.log("SUCCESS", f"Report saved: {report_path}", "green")
        except Exception as e:
            report_path = None
            self.log("WARN", f"Report generation failed: {e}", "orange")
        return {"osint": osint, "recon": recon, "redteam": redteam, "report_path": report_path}

    def _run_manifest(self, osint: dict, recon: dict, redteam: dict) -> dict:
        tools = list(dict.fromkeys(self.tools_executed))
        coverage_gaps = list(dict.fromkeys(
            list(osint.get("coverage_gaps", []))
            + list(recon.get("coverage_gaps", []))
            + list(redteam.get("coverage_gaps", []))
            + self.authorization_gaps
        ))
        external_sources = []
        if "cert_transparency" in tools:
            external_sources.append("crt.sh")
        if "internetdb_lookup" in tools:
            external_sources.append("Shodan InternetDB")
        if "cve_lookup" in tools:
            external_sources.append("NVD/OSV/Vulners CVE sources")
        if "epss_scoring" in tools:
            external_sources.append("FIRST EPSS")
        return {
            "target": self.target,
            "scope": {"domains": list(self.scope.domains), "ip_ranges": list(self.scope.ip_ranges)},
            "mode": self.mode,
            "profile": profile_summary(self.profile),
            "roe": {
                "loaded": self.roe is not None,
                "policy_path": self.roe.source_path if self.roe else "",
                "engagement_name": self.roe.name if self.roe else "",
                "allowed_profiles": self.roe.allowed_profiles if self.roe else [],
            },
            "started_at": self.started_at,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "tools_executed": tools,
            "caps": {
                "redteam_max_verifications": REDTEAM_MAX_VERIFICATIONS,
                "recon_additional_target_max": RECON_ADDITIONAL_TARGET_MAX,
                "external_lookup_timeout_s": EXTERNAL_LOOKUP_TIMEOUT,
                "tls_timeout_s": TLS_TIMEOUT,
                "asset_inventory_max_http_probes": ASSET_INVENTORY_MAX_HTTP_PROBES,
            },
            "coverage_gaps": coverage_gaps,
            "external_sources_used": external_sources,
            "safety_flags": [
                "authorized-scope-required",
                "non-destructive-redteam-verification",
                "raw-secrets-not-persisted",
                f"nmap-enabled={ENABLE_NMAP}",
                f"risky-method-checks-enabled={ENABLE_RISKY_METHOD_CHECKS}",
            ],
            "capability_audit": self.audit_events,
        }

    async def _build_recon_only_context(self) -> dict:
        target = self.target
        self.log("RECON", "Building recon-only target context", "")
        probe = await asyncio.to_thread(http_probe, f"https://{target}", self.validator)
        self.emit("tool_result", {"tool": "http_probe", "data": probe})
        asset_inventory = build_asset_inventory(
            target,
            dns={},
            subdomains={"discovered_subdomains": []},
            ct_data={"live_subdomains": [], "interesting_subdomains": []},
            internetdb={},
            passive_urls={},
            js_data={},
            http_data=probe,
            validator=self.validator,
        )
        return {
            "summary": f"Recon-only context for {target}. OSINT expansion was skipped by mode policy.",
            "technology_stack": probe.get("tech_signals", []),
            "_cpe_strings": probe.get("cpe_strings", []),
            "_tech_details": probe.get("tech_details", []),
            "_asset_inventory": asset_inventory,
            "asset_inventory": asset_inventory,
            "_js_data": {"endpoints": [], "secrets": [], "forms": [], "pages_crawled": []},
            "_passive_urls": {"discovered_urls": []},
            "_external_enrichment": {"internetdb": {}, "reverse_ip": {}},
            "_ct_subdomains": [],
            "subdomains": [],
            "collection_summary": {"http_url": probe.get("url") or f"https://{target}", "http_status": probe.get("status_code")},
            "coverage_gaps": [],
            "_missing_security_headers": probe.get("missing_security_headers", []),
            "_misconfigs": [],
        }

    # ── OSINT Phase ───────────────────────────────────────────────────────────
    async def _run_osint(self) -> dict:
        target = self.target
        self.log("OSINT", f"Initializing OSINT agent for {target}", "")
        await asyncio.sleep(0.1)

        # DNS
        self.log("TOOL", f"dns_lookup({target})", "dim")
        dns_data = await asyncio.to_thread(dns_lookup, target, self.validator)
        self.emit("tool_result", {"tool": "dns_lookup", "data": dns_data})
        if self.aborted(): return {}

        internetdb_data = {}
        resolved_ip = dns_data.get("resolved_ip", "")
        if resolved_ip:
            self.log("TOOL", f"internetdb_lookup({resolved_ip})", "dim")
            internetdb_data = await asyncio.to_thread(internetdb_lookup, resolved_ip)
            self.log(
                "OSINT",
                f"  -> InternetDB {internetdb_data.get('status', 'failed')}: "
                f"{len(internetdb_data.get('ports', []))} ports, "
                f"{len(internetdb_data.get('hostnames', []))} hostnames, "
                f"{len(internetdb_data.get('vulns', []))} vulns, "
                f"{len(internetdb_data.get('cpes', []))} CPEs",
                "green" if internetdb_data.get("status") == "success" else "orange",
            )
            self.emit("tool_result", {"tool": "internetdb_lookup", "data": internetdb_data})
        else:
            internetdb_data = {
                "ip": "",
                "ports": [],
                "hostnames": [],
                "vulns": [],
                "cpes": [],
                "tags": [],
                "source": "shodan_internetdb",
                "status": "skipped",
                "error": "no_resolved_ip",
            }

        # WHOIS
        self.log("TOOL", f"whois_lookup({target})", "dim")
        whois_data = await asyncio.to_thread(whois_lookup, target, self.validator)
        self.emit("tool_result", {"tool": "whois_lookup", "data": whois_data})
        if self.aborted(): return {}

        reverse_ip_data = {
            "query": resolved_ip or target,
            "hostnames": [],
            "ownership_unverified": True,
            "source": "hackertarget_reverse_ip",
            "status": "skipped",
            "error": "disabled",
        }
        if ENABLE_REVERSE_IP:
            reverse_query = resolved_ip or target
            self.log("TOOL", f"reverse_ip_lookup({reverse_query})", "dim")
            reverse_ip_data = await asyncio.to_thread(reverse_ip_lookup, reverse_query, self.validator)
            self.log(
                "OSINT",
                f"  -> Reverse IP {reverse_ip_data.get('status', 'failed')}: "
                f"{len(reverse_ip_data.get('hostnames', []))} hostnames "
                "(ownership unverified; not added to active scope)",
                "green" if reverse_ip_data.get("status") == "success" else "orange",
            )
            self.emit("tool_result", {"tool": "reverse_ip_lookup", "data": reverse_ip_data})

        if self.mode == "passive_only":
            subdomain_data = {"discovered_subdomains": [], "status": "skipped", "reason": "passive_only disables brute-force subdomain enumeration"}
            found_subs = []
            self.log("OSINT", "  -> Subdomain brute force skipped by passive_only mode", "dim")
        else:
            # Subdomain brute force
            subdomain_wordlist = load_subdomain_wordlist(SUBDOMAIN_WORDLIST_PATH, SUBDOMAIN_WORDLIST_MAX)
            self.log(
                "OSINT",
                f"Loaded {len(subdomain_wordlist)} subdomain candidates from {subdomain_wordlist_source(SUBDOMAIN_WORDLIST_PATH)}",
                "dim",
            )
            self.log("TOOL", f"subdomain_enumerate({target}, {len(subdomain_wordlist)} words)", "dim")
            subdomain_data = await asyncio.to_thread(
                subdomain_enumerate, target, subdomain_wordlist, self.validator
            )
            found_subs = subdomain_data.get("discovered_subdomains", [])
            for sub in found_subs:
                self.log("OSINT", f"  -> Subdomain: {sub['subdomain']} ({sub['ip']})", "green")
            self.emit("tool_result", {"tool": "subdomain_enumerate", "data": subdomain_data})
            if self.aborted(): return {}

        # ── Certificate Transparency (NEW) ────────────────────────────────────
        self.log("TOOL", f"cert_transparency_recon({target})", "dim")
        self.log("OSINT", "  -> Querying crt.sh certificate logs (passive)...", "")
        try:
            ct_data = await asyncio.to_thread(cert_transparency_recon, target, self.validator)
            ct_live = ct_data.get("live_count", 0)
            ct_interesting = len(ct_data.get("interesting_subdomains", []))
            self.log("OSINT", f"  -> CT found {ct_data.get('total_unique', 0)} unique subdomains ({ct_live} live, {ct_interesting} interesting)", "green")
            for sub in ct_data.get("interesting_subdomains", []):
                self.log("OSINT", f"  -> [CT] Interesting: {sub['subdomain']} ({sub.get('ip', 'unresolved')})", "red")
            self.emit("tool_result", {"tool": "cert_transparency", "data": ct_data})
        except Exception as e:
            self.log("WARN", f"CT recon failed: {e}", "orange")
            ct_data = {}
        if self.aborted(): return {}

        if self.mode == "passive_only":
            passive_url_data = {
                "robots": {"status": "skipped", "allow": [], "disallow": []},
                "sitemaps": {"status": "skipped", "urls": [], "child_sitemaps": []},
                "security_txt": {"status": "skipped", "status_code": 0, "fields": {}},
                "discovered_urls": [],
                "suggested_dorks": [
                    f"site:{target}",
                    f"site:{target} filetype:js",
                    f"site:{target} inurl:admin OR inurl:login",
                ],
                "coverage": {"passive_http_allowed": PASSIVE_HTTP_ALLOWED, "status": "skipped"},
            }
            if PASSIVE_HTTP_ALLOWED:
                passive_seed_url = f"https://{target}"
                self.log("TOOL", f"passive_url_discovery({passive_seed_url}) [passive_only]", "dim")
                passive_url_data = await asyncio.to_thread(passive_url_discovery, passive_seed_url, self.validator)
                self.emit("tool_result", {"tool": "passive_url_discovery", "data": passive_url_data})
            http_data = {"url": f"https://{target}", "status": "skipped", "tech_signals": [], "cpe_strings": [], "tech_details": [], "missing_security_headers": []}
            misconfig_data = {"findings": [], "restricted_findings": [], "budget_exhausted": False, "status": "skipped"}
            js_data = {"endpoints": [], "secrets": [], "internal_hosts": [], "cloud_resources": [], "script_count": 0, "forms": [], "pages_crawled": []}
            secret_queue = []
            osint_report = _ground_osint_report(
                target, dns_data, whois_data, subdomain_data, http_data, misconfig_data, ct_data, js_data, {},
                {"internetdb": internetdb_data, "reverse_ip": reverse_ip_data},
                passive_url_data,
                secret_queue,
            )
            asset_inventory = build_asset_inventory(
                target, dns_data, subdomain_data, ct_data, internetdb_data, passive_url_data, js_data, http_data, self.validator
            )
            osint_report.update({
                "_cpe_strings": list(internetdb_data.get("cpes", [])),
                "_tech_details": [],
                "_external_enrichment": {"internetdb": internetdb_data, "reverse_ip": reverse_ip_data},
                "_org_osint": whois_data.get("org_osint", {}),
                "_passive_urls": passive_url_data,
                "_suggested_dorks": passive_url_data.get("suggested_dorks", []),
                "_ct_data": ct_data,
                "_ct_subdomains": ct_data.get("live_subdomains", []),
                "_js_data": js_data,
                "_secret_verification_queue": secret_queue,
                "_asset_inventory": asset_inventory,
                "asset_inventory": asset_inventory,
                "_js_endpoints_count": 0,
                "_misconfigs": [],
                "_missing_security_headers": [],
            })
            self.log("SUCCESS", f"OSINT passive-only complete — CT names: {ct_data.get('total_unique', 0)}, risk score: {osint_report.get('risk_score', '?')}/10", "green")
            return osint_report

        # HTTP probe
        self.log("TOOL", f"http_probe(https://{target})", "dim")
        http_data = await asyncio.to_thread(http_probe, f"https://{target}", self.validator)
        if http_data.get("error"):
            self.log("WARN", f"  -> http_probe error: {http_data['error']}", "orange")
            if not http_data.get("tech_signals") and not http_data.get("status_code"):
                self.log(
                    "WARN",
                    "  -> http_probe returned no usable data — target may only be reachable on a port unavailable from this host. Recon phases will have limited coverage.",
                    "orange",
                )
        for tech in http_data.get("tech_signals", []):
            self.log("OSINT", f"  -> Tech detected: {tech}", "green")
        if http_data.get("cpe_strings"):
            self.log("OSINT", f"  -> CPE strings: {http_data['cpe_strings']}", "green")
        self.emit("tool_result", {"tool": "http_probe", "data": http_data})
        if self.aborted(): return {}

        # Passive URL Discovery
        passive_seed_url = http_data.get("url") or f"https://{target}"
        self.log("TOOL", f"passive_url_discovery({passive_seed_url})", "dim")
        try:
            passive_url_data = await asyncio.to_thread(
                passive_url_discovery, passive_seed_url, self.validator
            )
            robots = passive_url_data.get("robots", {})
            sitemaps = passive_url_data.get("sitemaps", {})
            security_txt = passive_url_data.get("security_txt", {})
            security_state = "present" if security_txt.get("status_code") == 200 else "missing"
            self.log(
                "OSINT",
                f"  -> Passive URLs: robots allow={len(robots.get('allow', []))}, "
                f"disallow={len(robots.get('disallow', []))}; "
                f"sitemap URLs={len(sitemaps.get('urls', []))}; "
                f"security.txt {security_state}; "
                f"dorks={len(passive_url_data.get('suggested_dorks', []))} manual-review suggestions",
                "green",
            )
            self.emit("tool_result", {"tool": "passive_url_discovery", "data": passive_url_data})
        except Exception as e:
            self.log("WARN", f"Passive URL discovery failed: {e}", "orange")
            passive_url_data = {}
        if self.aborted(): return {}

        # ── JS Intelligence (NEW) ─────────────────────────────────────────────
        js_seed_url = http_data.get("url") or f"https://{target}"
        js_fallback_urls = list(dict.fromkeys(
            list(http_data.get("candidate_urls", [])) + list(passive_url_data.get("discovered_urls", []))
        ))
        self.log("TOOL", f"js_intelligence({js_seed_url})", "dim")
        self.log("OSINT", "  -> Extracting endpoints/secrets from JavaScript...", "")
        try:
            js_data = await asyncio.to_thread(
                js_intelligence,
                js_seed_url,
                self.validator,
                seed_html=http_data.get("body_preview", ""),
                fallback_urls=js_fallback_urls,
            )
            js_data = _sanitize_js_data(js_data)
            secret_queue = build_secret_verification_queue(js_data)
            ep_count = len(js_data.get("endpoints", []))
            sec_count = len(js_data.get("secrets", []))
            page_count = len(js_data.get("pages_crawled", []))
            form_count = js_data.get("form_count", 0)
            self.log(
                "OSINT",
                f"  -> JS: {ep_count} endpoints, {sec_count} secrets, {js_data.get('script_count', 0)} scripts analyzed, "
                f"{page_count} pages crawled, {form_count} forms",
                "green",
            )
            for page in js_data.get("pages_crawled", [])[:5]:
                self.log("OSINT", f"  -> [CRAWL] {page['url']} ({page['routes']} routes, {page['forms']} forms)", "dim")
            for secret in js_data.get("secrets", []):
                self.log("OSINT", f"  -> [JS SECRET] {secret['type']}: {secret['value_preview']} [{secret['severity']}]", "red")
            for host in js_data.get("internal_hosts", []):
                self.log("OSINT", f"  -> [JS INTERNAL] {host}", "orange")
            for ep in js_data.get("endpoints", [])[:5]:
                self.log("OSINT", f"  -> [JS API] {ep}", "dim")
            self.emit("tool_result", {"tool": "js_intelligence", "data": js_data})
        except Exception as e:
            self.log("WARN", f"JS intelligence failed: {e}", "orange")
            js_data = {}
            secret_queue = []
        if self.aborted(): return {}

        asset_inventory = build_asset_inventory(
            target,
            dns_data,
            subdomain_data,
            ct_data,
            internetdb_data,
            passive_url_data,
            js_data,
            http_data,
            self.validator,
        )
        probe_assets = select_inventory_http_probe_targets(asset_inventory)
        if probe_assets:
            self.log("OSINT", f"  -> Asset inventory: probing {len(probe_assets)} high-priority in-scope hosts", "orange")
        for asset in probe_assets:
            if self.aborted(): return {}
            self.log("TOOL", f"http_probe({asset['url']}) [asset:{asset['source']}]", "dim")
            try:
                probe = await asyncio.to_thread(http_probe, asset["url"], self.validator)
                asset["http_probe"] = probe
                asset["tech_stack"] = list(dict.fromkeys(asset.get("tech_stack", []) + probe.get("tech_signals", [])))
                asset["cpe_strings"] = list(dict.fromkeys(asset.get("cpe_strings", []) + probe.get("cpe_strings", [])))
                if probe.get("missing_security_headers"):
                    asset["risk_hints"] = list(dict.fromkeys(asset.get("risk_hints", []) + ["missing security headers"]))
                asset["notable_findings_count"] = len(asset.get("risk_hints", []))
                self.emit("tool_result", {"tool": "asset_http_probe", "asset_id": asset["asset_id"], "data": probe})
            except Exception as e:
                asset.setdefault("http_probe", {})["error"] = str(e)
        asset_inventory = _merge_inventory_assets(asset_inventory)

        # Misconfigs
        misconfig_seed_url = http_data.get("url") or f"https://{target}"
        self.log("TOOL", f"check_common_misconfigs({misconfig_seed_url})", "dim")
        self.log("OSINT", "  -> Checking common exposed paths (time-bounded scan)...", "")
        misconfig_data = await asyncio.to_thread(
            check_common_misconfigs, misconfig_seed_url, self.validator
        )
        if misconfig_data.get("budget_exhausted"):
            self.log(
                "WARN",
                f"  -> Misconfig scan hit time budget after {misconfig_data.get('paths_checked', 0)}/"
                f"{misconfig_data.get('paths_total', 0)} paths",
                "orange",
            )
        for finding in misconfig_data.get("findings", []):
            color = "red" if finding["severity"] == "HIGH" else "orange"
            self.log("OSINT", f"  -> Exposed: {finding['path']} [{finding['severity']}]", color)
        self.emit("tool_result", {"tool": "misconfigs", "data": misconfig_data})

        # AI synthesis
        self.log("OSINT", "Synthesizing intelligence with AI...", "")
        osint_report = await self._ai_synthesize_osint(
            target, dns_data, whois_data, subdomain_data, http_data, misconfig_data, ct_data, js_data,
            {"internetdb": internetdb_data, "reverse_ip": reverse_ip_data},
            passive_url_data,
            secret_queue,
        )

        # Attach raw data for downstream phases
        osint_report["_cpe_strings"] = list(dict.fromkeys(
            list(http_data.get("cpe_strings", [])) + list(internetdb_data.get("cpes", []))
        ))
        osint_report["_tech_details"] = http_data.get("tech_details", [])
        osint_report["_external_enrichment"] = {"internetdb": internetdb_data, "reverse_ip": reverse_ip_data}
        osint_report["_org_osint"] = whois_data.get("org_osint", {
            "organization": "",
            "registrar": "",
            "emails": [],
            "abuse_emails": [],
            "source": "whois",
        })
        osint_report["_passive_urls"] = passive_url_data
        osint_report["_suggested_dorks"] = passive_url_data.get("suggested_dorks", [])
        osint_report["_ct_data"] = ct_data
        osint_report["_ct_subdomains"] = ct_data.get("live_subdomains", [])
        osint_report["_js_data"] = js_data
        osint_report["_secret_verification_queue"] = secret_queue
        osint_report["_asset_inventory"] = asset_inventory
        osint_report["asset_inventory"] = asset_inventory
        osint_report["_js_endpoints_count"] = len(js_data.get("endpoints", []))
        osint_report["_misconfigs"] = misconfig_data.get("findings", [])
        osint_report["_missing_security_headers"] = http_data.get("missing_security_headers", [])

        total_subs = len(found_subs) + ct_data.get("live_count", 0)
        self.log("SUCCESS",
            f"OSINT complete — {total_subs} subdomains, {len(js_data.get('endpoints', []))} JS endpoints, "
            f"risk score: {osint_report.get('risk_score', '?')}/10", "green")
        return osint_report

    async def _ai_synthesize_osint(self, target, dns, whois, subdomains, http, misconfigs, ct_data, js_data, external_enrichment=None, passive_urls=None, secret_verification_queue=None) -> dict:
        external_enrichment = external_enrichment or {}
        internetdb = external_enrichment.get("internetdb", {})
        reverse_ip = external_enrichment.get("reverse_ip", {})
        passive_urls = passive_urls or {}
        ct_interesting = [s["subdomain"] for s in ct_data.get("interesting_subdomains", [])]
        raw_data = {
            "dns": dns.get("records", {}),
            "resolved_ip": dns.get("resolved_ip", ""),
            "whois": whois.get("fields", {}),
            "whois_org_osint": redact_org_osint(whois.get("org_osint", {})),
            "subdomains_brute": [s["subdomain"] for s in subdomains.get("discovered_subdomains", [])],
            "ct_interesting_subdomains": ct_interesting,
            "ct_total_found": ct_data.get("total_unique", 0),
            "server_header": http.get("server_header", ""),
            "powered_by_header": http.get("powered_by_header", ""),
            "tech_signals": http.get("tech_signals", []),
            "cpe_strings": http.get("cpe_strings", []),
            "internetdb": {
                "status": internetdb.get("status"),
                "ports": internetdb.get("ports", []),
                "hostnames": internetdb.get("hostnames", []),
                "vulns": internetdb.get("vulns", []),
                "cpes": internetdb.get("cpes", []),
            },
            "reverse_ip": {
                "status": reverse_ip.get("status"),
                "hostnames_count": len(reverse_ip.get("hostnames", [])),
                "ownership_unverified": reverse_ip.get("ownership_unverified", True),
            },
            "js_endpoints_found": len(js_data.get("endpoints", [])),
            "js_secrets_found": len(js_data.get("secrets", [])),
            "secret_verification_queue": secret_verification_queue or [],
            "js_internal_hosts": js_data.get("internal_hosts", []),
            "js_cloud_resources": [r["value"] for r in js_data.get("cloud_resources", [])],
            "passive_url_discovery": {
                "robots_status": passive_urls.get("robots", {}).get("status_code", 0),
                "robots_allow_count": len(passive_urls.get("robots", {}).get("allow", [])),
                "robots_disallow_count": len(passive_urls.get("robots", {}).get("disallow", [])),
                "sitemap_url_count": len(passive_urls.get("sitemaps", {}).get("urls", [])),
                "security_txt_status": passive_urls.get("security_txt", {}).get("status_code", 0),
                "discovered_url_count": len(passive_urls.get("discovered_urls", [])),
                "suggested_dorks_count": len(passive_urls.get("suggested_dorks", [])),
            },
            "missing_security_headers": http.get("missing_security_headers", []),
            "misconfigs_found": misconfigs.get("findings", []),
            "http_status": http.get("status_code"),
        }

        prompt = f"""Analyze this OSINT data for {target} and return a structured intelligence report.

RAW DATA:
{json.dumps(raw_data, indent=2)}

Return ONLY valid JSON — no markdown, no preamble:
{{
  "summary": "2-3 sentence executive summary including CT findings and JS intelligence",
  "infrastructure": {{
    "hosting": "Use 'Unknown' unless directly supported by the provided evidence",
    "cdn": null,
    "org": "Registrant organization from whois or null"
  }},
  "subdomains": {json.dumps(subdomains.get("discovered_subdomains", [])[:10])},
  "technology_stack": ["copy only directly observed technologies with version"],
  "open_ports": [],
  "risk_score": 5,
  "misconfig_count": {len(misconfigs.get("findings", []))},
  "attack_surface_notes": "use only provided evidence; never infer unseen providers, products, or ports"
}}"""

        try:
            response = client.messages.create(
                model=DEFAULT_MODEL,
                max_tokens=900,
                messages=[{"role": "user", "content": prompt}],
                response_format="json",
                max_retries=2,
            )
            text = response.content[0].text
            cleaned = _clean_json(text)
            if not cleaned:
                raise ValueError(f"No JSON in response. Raw: {text[:300]!r}")
            return _ground_osint_report(target, dns, whois, subdomains, http, misconfigs, ct_data, js_data, json.loads(cleaned), external_enrichment, passive_urls, secret_verification_queue)
        except Exception as ex:
            self.log("WARN", f"AI synthesis failed: {ex}", "orange")

        return _ground_osint_report(target, dns, whois, subdomains, http, misconfigs, ct_data, js_data, {}, external_enrichment, passive_urls, secret_verification_queue)

    # ── Recon Phase ───────────────────────────────────────────────────────────
    async def _run_recon(self, osint_data: dict) -> dict:
        target = self.target
        self.log("RECON", "Initializing CVE & vulnerability hunter", "")
        await asyncio.sleep(0.1)

        port_scan_decision = self.authorize_action("port_scan", target)
        if ENABLE_NMAP and self.mode not in {"passive_only", "light_active"} and port_scan_decision["allowed"]:
            self.log("TOOL", f"port_scan({target}, common ports)", "dim")
            try:
                port_data = await asyncio.to_thread(
                    port_scan, target,
                    "21,22,23,25,80,443,3000,3306,5432,6379,8080,8443,9200,27017",
                    self.validator
                )
                for p in port_data.get("open_ports", []):
                    self.log("RECON", f"  -> {p}", "orange")
                self.emit("tool_result", {"tool": "port_scan", "data": port_data})
            except Exception as e:
                self.log("WARN", f"Port scan failed: {e}", "orange")
                port_data = {"open_ports": []}
        else:
            port_data = {"open_ports": [], "detected_tech": [], "service_inventory": [], "status": "skipped", "reason": f"mode={self.mode}, enable_nmap={ENABLE_NMAP}"}
            self.log("RECON", "  -> Port scan skipped by mode/config policy", "dim")
        if self.aborted(): return {}

        # Version disclosure and framework exposure
        version_seed_url = osint_data.get("collection_summary", {}).get("http_url") or f"https://{target}"
        self.log("TOOL", f"probe_version_disclosure({version_seed_url})", "dim")
        try:
            version_data = await asyncio.to_thread(probe_version_disclosure, version_seed_url, self.validator)
            coverage = version_data.get("coverage", {})
            self.log(
                "RECON",
                f"  -> Version disclosure: {coverage.get('exposed', 0)} exposed, "
                f"{coverage.get('protected', 0)} protected, {coverage.get('absent', 0)} absent",
                "orange" if coverage.get("exposed", 0) else "green",
            )
            self.emit("tool_result", {"tool": "probe_version_disclosure", "data": version_data})
        except Exception as e:
            self.log("WARN", f"Version disclosure probe failed: {e}", "orange")
            version_data = {"base_url": version_seed_url, "paths": [], "findings": [], "coverage": {"error": str(e)}}
        osint_data["_version_disclosure"] = version_data
        if self.aborted(): return {}

        additional_targets = build_additional_recon_targets(
            target,
            osint_data,
            max_targets=RECON_ADDITIONAL_TARGET_MAX,
            validator=self.validator,
        )
        additional_results = {
            "targets": additional_targets,
            "probes": [],
            "coverage": {"targets_total": len(additional_targets), "probed": 0, "failed": 0},
        }
        additional_cpes = []
        version_bases_seen = set()
        if additional_targets:
            self.log("RECON", f"  -> Additional HTTP targets from OSINT: {len(additional_targets)}", "orange")
        for item in additional_targets:
            if self.aborted(): return {}
            self.log("TOOL", f"http_probe({item['url']}) [additional:{item['source']}]", "dim")
            try:
                probe = await asyncio.to_thread(http_probe, item["url"], self.validator)
                for cpe in probe.get("cpe_strings", []):
                    if cpe not in additional_cpes:
                        additional_cpes.append(cpe)
                entry = {
                    **item,
                    "status_code": probe.get("status_code", 0),
                    "tech_signals": probe.get("tech_signals", []),
                    "missing_headers": probe.get("missing_security_headers", []),
                    "cpe_strings": probe.get("cpe_strings", []),
                    "error": probe.get("error", ""),
                }
                if item["priority"] <= 3:
                    base = _base_url_for_target(target, {"collection_summary": {"http_url": item["url"]}})
                    if base not in version_bases_seen:
                        version_bases_seen.add(base)
                        try:
                            entry["version_disclosure"] = await asyncio.to_thread(
                                probe_version_disclosure, base, self.validator
                            )
                        except Exception as ex:
                            entry["version_disclosure"] = {"base_url": base, "paths": [], "findings": [], "coverage": {"error": str(ex)}}
                additional_results["probes"].append(entry)
                additional_results["coverage"]["probed"] += 1
            except Exception as e:
                additional_results["coverage"]["failed"] += 1
                additional_results["probes"].append({**item, "status_code": 0, "tech_signals": [], "missing_headers": [], "cpe_strings": [], "error": str(e)})
        osint_data["_additional_targets"] = additional_results
        asset_inventory = merge_additional_recon_into_inventory(
            osint_data.get("_asset_inventory") or osint_data.get("asset_inventory", []),
            additional_results,
            self.validator,
        )
        osint_data["_asset_inventory"] = asset_inventory
        osint_data["asset_inventory"] = asset_inventory

        tls_seed_url = version_seed_url if version_seed_url.startswith("https://") else f"https://{target}"
        self.log("TOOL", f"tls_audit({tls_seed_url})", "dim")
        try:
            tls_data = await asyncio.to_thread(tls_audit, tls_seed_url, self.validator)
            self.log(
                "RECON",
                f"  -> TLS: {len(tls_data.get('findings', []))} findings, "
                f"selected {tls_data.get('selected_tls_version', 'unknown') or 'unknown'}",
                "orange" if tls_data.get("findings") else "green",
            )
            self.emit("tool_result", {"tool": "tls_audit", "data": tls_data})
        except Exception as e:
            self.log("WARN", f"TLS audit failed: {e}", "orange")
            tls_data = {"target": target, "port": 443, "certificate": {}, "protocols": {}, "selected_cipher": "", "findings": [], "coverage": {"error": str(e)}}

        additional_tls = []
        tls_seen = {_recon_url_key(tls_seed_url)}
        for item in additional_targets:
            if len(additional_tls) >= TLS_ADDITIONAL_TARGET_MAX:
                break
            if item.get("priority", 99) > 3 or not item.get("url", "").startswith("https://"):
                continue
            base = _base_url_for_target(target, {"collection_summary": {"http_url": item["url"]}})
            key = _recon_url_key(base)
            if key in tls_seen:
                continue
            tls_seen.add(key)
            try:
                additional_tls.append(await asyncio.to_thread(tls_audit, base, self.validator))
            except Exception as ex:
                additional_tls.append({"target": urllib.parse.urlparse(base).hostname or base, "port": 443, "certificate": {}, "protocols": {}, "selected_cipher": "", "findings": [], "coverage": {"error": str(ex)}})
        if additional_tls:
            tls_data["additional"] = additional_tls
        osint_data["_tls_audit"] = tls_data

        # CVE lookups
        cve_results = []
        cve_source_coverage = []
        cpe_strings = list(osint_data.get("_cpe_strings", []))
        tech_stack = list(osint_data.get("technology_stack", []))
        per_asset_recon = {}
        cpe_to_assets: dict[str, list[str]] = {}
        for asset in osint_data.get("_asset_inventory", []) or []:
            asset_id = asset.get("asset_id", "")
            if not asset_id:
                continue
            per_asset_recon[asset_id] = {
                "host": asset.get("host", ""),
                "url": asset.get("url", ""),
                "source": asset.get("source", ""),
                "priority": asset.get("priority", 9),
                "tech_stack": asset.get("tech_stack", []),
                "cpe_strings": asset.get("cpe_strings", []),
                "cve_queries": [],
                "cve_count": 0,
            }
            for cpe in asset.get("cpe_strings", []) or []:
                cpe_to_assets.setdefault(cpe, []).append(asset_id)
                if cpe not in cpe_strings:
                    cpe_strings.append(cpe)
            for tech in asset.get("tech_stack", []) or []:
                if tech not in tech_stack:
                    tech_stack.append(tech)
        service_inventory = port_data.get("service_inventory", [])
        service_cpes = []
        for service in service_inventory:
            for cpe in service.get("candidate_cpes", []):
                if cpe not in service_cpes:
                    service_cpes.append(cpe)
            product = service.get("product", "")
            version = service.get("version", "")
            if product:
                label = f"{product} {version}".strip()
                if label not in tech_stack:
                    tech_stack.append(label)
        port_cpes = []
        if not service_cpes:
            port_cpes = [
                t["cpe"] for t in port_data.get("detected_tech", [])
                if isinstance(t, dict) and t.get("cpe")
            ]
        if service_cpes:
            for cpe in service_cpes:
                if cpe not in cpe_strings:
                    cpe_strings.append(cpe)
            self.log("RECON", f"  -> Reusing {len(service_cpes)} structured service CPE candidates", "orange")
        if additional_cpes:
            for cpe in additional_cpes:
                if cpe not in cpe_strings:
                    cpe_strings.append(cpe)
            self.log("RECON", f"  -> Reusing {len(additional_cpes)} CPEs from additional HTTP targets", "orange")
        if port_cpes:
            for cpe in port_cpes:
                if cpe not in cpe_strings:
                    cpe_strings.append(cpe)
            detected_names = [t.get("name") for t in port_data.get("detected_tech", []) if t.get("name")]
            for name in detected_names:
                if name not in tech_stack:
                    tech_stack.append(name)
            osint_data["technology_stack"] = tech_stack
            self.log("RECON", f"  -> Reusing {len(port_cpes)} service fingerprints from port scan", "orange")
        elif service_inventory:
            osint_data["technology_stack"] = tech_stack

        skip_cve_lookup = not cpe_strings and not tech_stack
        if skip_cve_lookup:
            self.log(
                "WARN",
                "Skipping CVE lookups due to no detected technology after service enumeration. This indicates limited collection visibility, not an absence of vulnerabilities.",
                "orange",
            )

        if cpe_strings:
            self.log("RECON", f"CVE lookups for {len(cpe_strings)} detected components...", "")
            for cpe in cpe_strings[:4]:
                self.log("TOOL", f"fetch_cve_data({cpe})", "dim")
                try:
                    cves = await asyncio.to_thread(fetch_cve_data, cpe)
                    total = cves.get("total", 0)
                    if total > 0:
                        self.log("RECON", f"  -> {total} CVEs found for {cpe}", "orange")
                    cve_results.extend(cves.get("vulnerabilities", [])[:4])
                    for asset_id in cpe_to_assets.get(cpe, []):
                        per_asset_recon.setdefault(asset_id, {"cve_queries": [], "cve_count": 0})
                        per_asset_recon[asset_id]["cve_queries"].append(cpe)
                        per_asset_recon[asset_id]["cve_count"] += len(cves.get("vulnerabilities", []))
                    cve_source_coverage.append({"query": cpe, "coverage": cves.get("coverage", {})})
                    self.emit("tool_result", {"tool": "cve_lookup", "cpe": cpe, "data": cves})
                except Exception as e:
                    self.log("WARN", f"CVE lookup failed for {cpe}: {e}", "orange")
                if self.aborted(): return {}
                await asyncio.sleep(0.6)
        elif tech_stack:
            for tech in osint_data.get("technology_stack", [])[:3]:
                cpe = tech.lower().replace(" ", ":").replace("/", ":")
                self.log("TOOL", f"fetch_cve_data({cpe}) [keyword]", "dim")
                try:
                    cves = await asyncio.to_thread(fetch_cve_data, cpe)
                    if cves.get("total", 0) > 0:
                        self.log("RECON", f"  -> {cves['total']} CVEs for {tech}", "orange")
                    cve_results.extend(cves.get("vulnerabilities", [])[:4])
                    cve_source_coverage.append({"query": cpe, "coverage": cves.get("coverage", {})})
                    self.emit("tool_result", {"tool": "cve_lookup", "tech": tech, "data": cves})
                except Exception as e:
                    self.log("WARN", f"CVE lookup failed for {tech}: {e}", "orange")
                if self.aborted(): return {}
                await asyncio.sleep(0.6)

        cve_results = _dedupe_cves(cve_results)

        # ── EPSS Scoring (NEW) ────────────────────────────────────────────────
        if cve_results:
            self.log("TOOL", f"epss_scoring({len(cve_results)} CVEs)", "dim")
            self.log("RECON", "  -> Fetching exploitation probability scores...", "")
            try:
                cve_results = await asyncio.to_thread(enrich_cves_with_epss, cve_results)
                epss_sum = epss_summary(cve_results)
                p1 = epss_sum.get("p1_immediate", 0)
                high_risk = epss_sum.get("high_exploitation_risk", 0)
                if p1 > 0:
                    self.log("RECON", f"  -> EPSS: {p1} P1-IMMEDIATE CVEs, {high_risk} with >10% exploit probability", "red")
                else:
                    self.log("RECON", f"  -> EPSS: {high_risk} CVEs with elevated exploit probability", "orange")
                for cve in cve_results[:3]:
                    if cve.get("epss", 0) > 0.01:
                        self.log("RECON", f"  -> {cve['id']}: EPSS {cve['epss_percent']}% — {cve.get('priority', '')}", "orange")
                self.emit("tool_result", {"tool": "epss_scoring", "data": {"cves": cve_results, "summary": epss_sum}})
            except Exception as e:
                self.log("WARN", f"EPSS scoring failed: {e}", "orange")
                epss_sum = {}
        else:
            epss_sum = {}

        nuclei_data = await asyncio.to_thread(
            run_nuclei,
            version_seed_url,
            self.validator,
            self.profile.value,
            self.roe,
        )
        if nuclei_data.get("status") not in {"skipped", "blocked_by_roe"}:
            self.emit("tool_result", {"tool": "nuclei", "data": nuclei_data})
            self.log("RECON", f"  -> Nuclei {nuclei_data.get('profile', 'safe')}: {len(nuclei_data.get('findings', []))} matches", "orange")
        elif nuclei_data.get("reason"):
            self.log("RECON", f"  -> Nuclei skipped: {nuclei_data.get('reason')}", "dim")

        # AI vulnerability analysis
        self.log("RECON", "Analyzing vulnerabilities with AI...", "")
        vuln_report = await self._ai_vuln_analysis(target, osint_data, port_data, cve_results)

        # Tag with MITRE and attach EPSS summary
        vuln_report["high_findings"] = map_to_mitre(vuln_report.get("high_findings", []))
        vuln_report["critical_findings"] = map_to_mitre(vuln_report.get("critical_findings", []))
        vuln_report["medium_findings"] = map_to_mitre(vuln_report.get("medium_findings", []))
        vuln_report["cve_matches"] = cve_results
        vuln_report["nuclei"] = nuclei_data
        for finding in nuclei_data.get("findings", []):
            severity = finding.get("severity", "INFO").upper()
            normalized = {
                "title": finding.get("title", "Nuclei finding"),
                "description": finding.get("description", ""),
                "severity": severity,
                "affected": finding.get("affected", ""),
                "confidence": "HIGH",
                "source": "nuclei",
                "evidence": finding.get("evidence", {}),
                "template_id": finding.get("template_id", ""),
            }
            if severity == "CRITICAL":
                vuln_report.setdefault("critical_findings", []).append(normalized)
            elif severity == "HIGH":
                vuln_report.setdefault("high_findings", []).append(normalized)
            elif severity in {"MEDIUM", "LOW"}:
                vuln_report.setdefault("medium_findings", []).append(normalized)
        vuln_report["_version_disclosure"] = version_data
        vuln_report["version_disclosure"] = version_data
        vuln_report["_additional_targets"] = additional_results
        vuln_report["additional_targets"] = additional_results
        vuln_report["_tls_audit"] = tls_data
        vuln_report["tls_audit"] = tls_data
        vuln_report["_epss_summary"] = epss_sum
        vuln_report["_open_ports"] = port_data.get("open_ports", [])
        vuln_report["_service_inventory"] = port_data.get("service_inventory", [])
        vuln_report["_service_fingerprints"] = port_data.get("detected_tech", [])
        vuln_report["_cve_source_coverage"] = cve_source_coverage
        vuln_report["_per_asset_recon"] = per_asset_recon
        vuln_report["per_asset_recon"] = per_asset_recon
        for asset in osint_data.get("_asset_inventory", []) or []:
            recon_entry = per_asset_recon.get(asset.get("asset_id", ""), {})
            asset["notable_findings_count"] = asset.get("notable_findings_count", 0) + recon_entry.get("cve_count", 0)
        vuln_report["asset_inventory"] = osint_data.get("_asset_inventory", [])

        total = (len(vuln_report.get("critical_findings", [])) +
                 len(vuln_report.get("high_findings", [])) +
                 len(vuln_report.get("medium_findings", [])))
        self.log("SUCCESS", f"Recon complete — {total} findings, {len(cve_results)} CVEs, "
                 f"{epss_sum.get('p1_immediate', 0)} P1-immediate", "green")
        return vuln_report

    async def _ai_vuln_analysis(self, target, osint, ports, cves) -> dict:
        js_data = osint.get("_js_data", {})
        prompt = f"""Analyze this data for {target} and produce a vulnerability assessment.

TECH STACK: {osint.get("technology_stack", [])}
CPE STRINGS: {osint.get("_cpe_strings", [])}
MISCONFIGS: {osint.get("misconfig_count", 0)} found
OPEN PORTS: {ports.get("open_ports", [])}
JS ENDPOINTS FOUND: {osint.get("_js_endpoints_count", 0)}
JS SECRETS FOUND: {len(js_data.get("secrets", []))}
JS INTERNAL HOSTS: {js_data.get("internal_hosts", [])}
CVE MATCHES (with EPSS scores):
{json.dumps([{
    "id": c.get("id"), "cvss": c.get("cvss_score"),
    "epss_percent": c.get("epss_percent", 0),
    "priority": c.get("priority", ""),
    "description": c.get("description", "")[:100]
} for c in cves[:8]], indent=2)}

Return ONLY valid JSON — no markdown:
{{
  "critical_findings": [{{"title": "...", "description": "...", "cvss_score": 9.0, "affected": "..."}}],
  "high_findings": [{{"title": "...", "description": "...", "cvss_score": 7.5, "affected": "..."}}],
  "medium_findings": [{{"title": "...", "description": "...", "cvss_score": 5.0, "affected": "..."}}],
  "attack_vectors": ["list attack vectors"],
  "scan_summary": "include EPSS context — which CVEs are actively exploited"
}}

Use only provided evidence. Do not invent products, versions, open ports, or recommendations not present in the input. Include JS secrets as critical findings if present. Reference EPSS scores in your analysis."""

        try:
            response = client.messages.create(
                model=DEFAULT_MODEL,
                max_tokens=1200,
                messages=[{"role": "user", "content": prompt}],
                response_format="json",
                max_retries=2,
            )
            text = response.content[0].text
            cleaned = _clean_json(text)
            if not cleaned:
                raise ValueError(f"No JSON in response. Raw: {text[:300]!r}")
            return _ground_vuln_report(target, osint, ports, cves, json.loads(cleaned))
        except Exception as ex:
            self.log("WARN", f"AI vuln analysis failed: {ex}", "orange")

        return _ground_vuln_report(target, osint, ports, cves, {})

    # ── Red Team Phase ────────────────────────────────────────────────────────
    async def _run_redteam(self, vuln_data: dict, osint_data: dict) -> dict:
        target = self.target
        self.log("REDTEAM", "Initializing red team agent — authorized scope only", "red")
        await asyncio.sleep(0.1)

        test_results = []
        advanced_profile = self.profile in {CapabilityProfile.ADVANCED, CapabilityProfile.CUSTOM}
        verification_assets = sorted(
            [
                asset for asset in (vuln_data.get("asset_inventory") or osint_data.get("_asset_inventory", []) or [])
                if asset.get("in_scope") and asset.get("url")
            ],
            key=lambda item: (item.get("priority", 9), -len(item.get("cpe_strings", [])), item.get("host", "")),
        )
        verification_url = verification_assets[0]["url"] if verification_assets else f"https://{target}"
        valid_verification_url, _ = self.validator.validate(verification_url)
        if not valid_verification_url:
            verification_url = f"https://{target}"
        findings_to_test = list(vuln_data.get("critical_findings", [])) + list(vuln_data.get("high_findings", []))
        if advanced_profile:
            findings_to_test.extend(vuln_data.get("medium_findings", []))
        else:
            for finding in vuln_data.get("medium_findings", []):
                title = finding.get("title", "").lower()
                if any(marker in title for marker in ["missing security headers", "cors", "exposed path", "clickjacking", "open redirect", "http method", "tls"]):
                    findings_to_test.append(finding)
            findings_to_test = findings_to_test[:REDTEAM_MAX_VERIFICATIONS]

        def blocked_result(action: str, finding_name: str, decision: dict) -> dict:
            result = verification_result(
                VerificationStatus.BLOCKED_BY_ROE,
                "Update the signed Rules of Engagement only if the operator and asset owner approve this verification action.",
                action=action,
                reason=decision.get("reason", ""),
                matched_rule=decision.get("matched_rule", ""),
                confirmed=False,
            )
            item = {"test": action, "finding": finding_name, "result": result, "authorization": decision}
            self.emit("tool_result", {"tool": action, "data": result})
            return item

        def authorize_verification(action: str, finding_name: str, method: str = "GET", url: str = "") -> dict | None:
            decision = self.authorize_action(
                action,
                target=url or verification_url,
                method=method,
                path=urllib.parse.urlparse(url or verification_url).path or "/",
            )
            if decision["allowed"]:
                return decision
            test_results.append(blocked_result(action, finding_name, decision))
            return None

        if advanced_profile:
            phase_decision = self.authorize_action(
                "advanced_verification",
                target=verification_url,
                method="GET",
                path=urllib.parse.urlparse(verification_url).path or "/",
            )
            if not phase_decision["allowed"]:
                for finding in findings_to_test:
                    test_results.append(blocked_result(
                        "advanced_verification",
                        finding.get("title", "Unknown"),
                        phase_decision,
                    ))
                findings_to_test = []

        for finding in findings_to_test:
            if not advanced_profile and len(test_results) >= REDTEAM_MAX_VERIFICATIONS:
                break
            if self.aborted(): break
            name = finding.get("title", "Unknown")
            self.log("TOOL", f"test_vulnerability({name[:50]})", "dim")
            await asyncio.sleep(0.8)
            try:
                if "exposed path" in name.lower():
                    if advanced_profile and not authorize_verification("auth_panel_discovery", name):
                        continue
                    result = await asyncio.to_thread(
                        _test_exposed_path, verification_url, finding, self.validator
                    )
                    test_results.append({"test": "exposed_path", "finding": name, "result": result})
                    self.emit("tool_result", {"tool": "exposed_path_test", "data": result})
                elif any(kw in name.lower() for kw in ["cred", "auth", "admin", "login"]):
                    if advanced_profile and not authorize_verification("auth_panel_discovery", name):
                        continue
                    result = await asyncio.to_thread(
                        discover_auth_panels, verification_url, self.validator
                    )
                    test_results.append({"test": "auth_panel_discovery", "finding": name, "result": result})
                    self.emit("tool_result", {"tool": "auth_panel_discovery", "data": result})
                elif "cors" in name.lower():
                    if advanced_profile and not authorize_verification("cors_verification", name):
                        continue
                    result = await asyncio.to_thread(
                        _test_cors, verification_url, self.validator
                    )
                    test_results.append({"test": "cors", "finding": name, "result": result})
                    self.emit("tool_result", {"tool": "cors_test", "data": result})
                elif "missing security headers" in name.lower():
                    if advanced_profile and not authorize_verification("clickjacking_verification", name):
                        continue
                    result = await asyncio.to_thread(
                        _test_missing_security_headers, verification_url, finding, self.validator
                    )
                    test_results.append({"test": "missing_security_headers", "finding": name, "result": result})
                    self.emit("tool_result", {"tool": "missing_header_test", "data": result})
                elif "open redirect" in name.lower() or "redirect" in name.lower():
                    if advanced_profile and not authorize_verification("open_redirect_verification", name):
                        continue
                    result = await asyncio.to_thread(test_open_redirect, verification_url, self.validator)
                    test_results.append({"test": "open_redirect", "finding": name, "result": result})
                    self.emit("tool_result", {"tool": "open_redirect", "data": result})
                elif "method" in name.lower() or "trace" in name.lower():
                    if advanced_profile and not authorize_verification("http_method_verification", name, method="OPTIONS"):
                        continue
                    risky_methods = []
                    if advanced_profile and self.roe:
                        for method in self.roe.risky_methods_allowed:
                            if method not in {"PUT", "DELETE"}:
                                continue
                            decision = self.authorize_action(
                                "risky_method_check",
                                target=verification_url,
                                method=method,
                                path=urllib.parse.urlparse(verification_url).path or "/",
                            )
                            if decision["allowed"]:
                                risky_methods.append(method)
                            else:
                                test_results.append(blocked_result("risky_method_check", name, decision))
                    result = await asyncio.to_thread(
                        test_http_methods,
                        verification_url,
                        self.validator,
                        risky_methods,
                    )
                    test_results.append({"test": "http_methods", "finding": name, "result": result})
                    self.emit("tool_result", {"tool": "http_methods", "data": result})
                elif "clickjack" in name.lower() or "frame" in name.lower():
                    if advanced_profile and not authorize_verification("clickjacking_verification", name):
                        continue
                    result = await asyncio.to_thread(test_clickjacking, verification_url, self.validator)
                    test_results.append({"test": "clickjacking", "finding": name, "result": result})
                    self.emit("tool_result", {"tool": "clickjacking", "data": result})
                elif "host header" in name.lower():
                    if advanced_profile and not authorize_verification("host_header_verification", name):
                        continue
                    result = await asyncio.to_thread(test_host_header_injection, verification_url, self.validator)
                    test_results.append({"test": "host_header_injection", "finding": name, "result": result})
                    self.emit("tool_result", {"tool": "host_header_injection", "data": result})
                else:
                    self.log("REDTEAM", f"  -> Passive check: {name[:50]}", "")
                    await asyncio.sleep(0.5)
                    test_results.append({
                        "test": "manual_followup",
                        "finding": name,
                        "result": verification_result(
                            VerificationStatus.NEEDS_MANUAL_FOLLOWUP,
                            "Select a finding-specific, non-destructive manual validation procedure and record evidence before making an exploitation claim.",
                            confirmed=False,
                            manual_verification_needed=True,
                        ),
                    })
            except Exception as e:
                self.log("WARN", f"  -> Test error: {e}", "orange")
                test_results.append({
                    "test": "verification_error",
                    "finding": name,
                    "result": verification_result(
                        VerificationStatus.NEEDS_MANUAL_FOLLOWUP,
                        "Repeat the verification manually with an intercepting proxy and preserve the request and response evidence.",
                        error=str(e),
                        confirmed=False,
                    ),
                })

        for item in vuln_data.get("_additional_targets", {}).get("targets", []):
            if not advanced_profile and len(test_results) >= REDTEAM_MAX_VERIFICATIONS:
                break
            if item.get("priority", 99) <= 3:
                if advanced_profile and not authorize_verification("api_endpoint_discovery", item.get("reason", "additional target"), url=item["url"]):
                    continue
                result = await asyncio.to_thread(enumerate_api_endpoints, item["url"], self.validator)
                test_results.append({"test": "api_endpoint_discovery", "finding": item.get("reason", "additional target"), "result": result})
                self.emit("tool_result", {"tool": "api_endpoint_discovery", "data": result})

        # ── Attack Graph + Kill Chains (NEW) ──────────────────────────────────
        self.log("REDTEAM", "Building attack graph...", "red")
        try:
            graph = await asyncio.to_thread(
                build_attack_graph,
                target,
                osint_data,
                vuln_data,
                osint_data.get("_ct_data", {}),
                osint_data.get("_js_data", {}),
                test_results,
            )
            self.log("REDTEAM", f"  -> Graph: {len(graph.nodes)} nodes, {len(graph.get_critical_paths())} critical paths", "red")

            self.log("REDTEAM", "Generating kill chains with AI...", "red")
            kill_chain_data = await asyncio.to_thread(generate_kill_chains, graph, client, DEFAULT_MODEL)

            chains = kill_chain_data.get("kill_chains", [])
            for chain in chains:
                self.log("REDTEAM", f"  -> Kill chain: {chain.get('name')} [{chain.get('likelihood')}]", "red")

            self.emit("tool_result", {"tool": "attack_graph", "data": {
                "graph_summary": graph.to_dict(),
                "kill_chains": kill_chain_data
            }})
        except Exception as e:
            self.log("WARN", f"Attack graph failed: {e}", "orange")
            kill_chain_data = {"kill_chains": [], "worst_case_scenario": "", "overall_chain_risk": "UNKNOWN"}
            graph = None

        self.log("REDTEAM", "Synthesizing red team report...", "")
        redteam_report = await self._ai_redteam_synthesis(target, vuln_data, test_results, kill_chain_data)
        redteam_report["profile"] = self.profile.value
        redteam_report["profile_badge"] = self.profile.value.upper()
        if self.profile == CapabilityProfile.LAB:
            lab_decision = self.authorize_action("lab_exploit_simulation", target=self.target)
            if lab_decision["allowed"]:
                evidence_refs = [
                    ref
                    for finding in (
                        vuln_data.get("critical_findings", [])
                        + vuln_data.get("high_findings", [])
                        + vuln_data.get("medium_findings", [])
                    )
                    for ref in finding.get("evidence_refs", [])
                ]
                simulations = await asyncio.to_thread(
                    run_lab_simulations,
                    self.target,
                    None,
                    LAB_MANIFEST_PATH,
                    evidence_refs[:20],
                )
                redteam_report["lab_simulations"] = simulations
                self.emit("tool_result", {"tool": "lab_exploit_simulation", "data": {
                    "lab_only": True,
                    "simulations": simulations,
                }})
            else:
                redteam_report["lab_simulations"] = []
                redteam_report.setdefault("verification_results", []).append({
                    "test": "lab_exploit_simulation",
                    "finding": "Lab exploit simulation",
                    "result": verification_result(
                        VerificationStatus.BLOCKED_BY_ROE,
                        "Use a localhost or manifest-declared demo asset and explicitly enable lab simulation.",
                        reason=lab_decision.get("reason", ""),
                        matched_rule=lab_decision.get("matched_rule", ""),
                    ),
                })
        self.log("SUCCESS", f"Red team complete — risk: {redteam_report.get('overall_risk')}, "
                 f"{len(redteam_report.get('kill_chains', []))} kill chains", "green")
        return redteam_report

    async def _ai_redteam_synthesis(self, target, vulns, test_results, kill_chain_data) -> dict:
        cve_matches = vulns.get("cve_matches", [])
        all_findings = vulns.get("critical_findings", []) + vulns.get("high_findings", [])
        if self.profile in {CapabilityProfile.ADVANCED, CapabilityProfile.CUSTOM}:
            all_findings += vulns.get("medium_findings", [])
        max_cvss = max((c.get("cvss_score") or 0 for c in cve_matches), default=0)
        max_epss = max((c.get("epss", 0) for c in cve_matches), default=0)
        has_eol = any("5.6" in str(t) or "end-of-life" in str(t).lower()
                      for t in vulns.get("attack_vectors", []) + [vulns.get("scan_summary", "")])

        if max_cvss >= 9.0 or vulns.get("critical_findings"):
            risk_floor = "CRITICAL"
        elif max_cvss >= 7.0 or vulns.get("high_findings") or has_eol:
            risk_floor = "HIGH"
        elif max_cvss >= 4.0:
            risk_floor = "MEDIUM"
        else:
            risk_floor = "LOW"

        prompt = f"""Produce a final red team assessment for {target}.

RISK FLOOR: {risk_floor} (do not rate lower than this)
MAX CVE CVSS: {max_cvss} | MAX EPSS: {max_epss*100:.1f}%
KILL CHAINS IDENTIFIED: {len(kill_chain_data.get("kill_chains", []))}
WORST CASE: {kill_chain_data.get("worst_case_scenario", "N/A")}

VULNERABILITIES:
{json.dumps(all_findings[:5], indent=2)}

CVEs (with EPSS):
{json.dumps([{"id": c.get("id"), "cvss": c.get("cvss_score"), "epss_pct": c.get("epss_percent", 0), "priority": c.get("priority", "")} for c in cve_matches[:5]], indent=2)}

TEST RESULTS: {json.dumps(test_results, indent=2)}

Rules:
- For advanced/custom profiles, account for every high/medium evidence-backed finding with a relevant non-destructive verification result or an explicit blocked_by_roe/needs_manual_followup status.
- Never claim exploitation. Distinguish confirmed from strongly_indicated and not_reproduced.
- Preserve the next_best_manual_test for each verification result.
- Do not attempt credentials, destructive writes, exploitation, or out-of-scope requests.
- overall_risk must be >= {risk_floor}
- Reference EPSS scores and kill chains in summary
- Only recommend actions directly supported by provided evidence; never invent unseen products or version numbers

Return ONLY valid JSON:
{{
  "confirmed_vulnerabilities": [],
  "kill_chains": {json.dumps(kill_chain_data.get("kill_chains", []))},
  "proof_of_concepts": [],
  "overall_risk": "{risk_floor}",
  "engagement_summary": "paragraph covering CVEs, EPSS scores, kill chains, and business risk",
  "recommendations": [
    {{"priority": "CRITICAL", "recommendation": "specific fix with version"}},
    {{"priority": "HIGH", "recommendation": "specific fix"}},
    {{"priority": "HIGH", "recommendation": "specific fix"}},
    {{"priority": "MEDIUM", "recommendation": "specific fix"}}
  ]
}}"""

        try:
            response = client.messages.create(
                model=DEFAULT_MODEL,
                max_tokens=1500,
                messages=[{"role": "user", "content": prompt}],
                response_format="json",
                max_retries=2,
            )
            text = response.content[0].text
            cleaned = _clean_json(text)
            if not cleaned:
                raise ValueError(f"No JSON in response. Raw: {text[:300]!r}")
            result = json.loads(cleaned)
            if isinstance(result, list):
                result = {
                    "confirmed_vulnerabilities": [],
                    "kill_chains": result,
                    "proof_of_concepts": [],
                    "overall_risk": risk_floor,
                    "engagement_summary": "",
                    "recommendations": [],
                }
            if not isinstance(result, dict):
                raise ValueError(f"Unexpected red team response shape: {type(result).__name__}")

            # Enforce risk floor
            risk_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            ai_risk = result.get("overall_risk", "LOW").upper()
            if risk_order.index(ai_risk) < risk_order.index(risk_floor):
                self.log("WARN", f"AI rated {ai_risk}, overriding to floor {risk_floor}", "orange")
                result["overall_risk"] = risk_floor

            # Always attach kill chains even if AI response didn't include them
            if not result.get("kill_chains"):
                result["kill_chains"] = kill_chain_data.get("kill_chains", [])

            return _ground_redteam_report(target, vulns, test_results, kill_chain_data, result)
        except Exception as ex:
            self.log("WARN", f"AI red team synthesis failed: {ex}", "orange")

        return _ground_redteam_report(target, vulns, test_results, kill_chain_data, {})


# ── Test helpers ──────────────────────────────────────────────────────────────
def _discover_auth_panels(url: str, scope: ScopeValidator) -> dict:
    return discover_auth_panels(url, scope)


def _test_cors(url: str, scope: ScopeValidator) -> dict:
    import urllib.request, ssl
    scope.assert_in_scope(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={
            "Origin": "https://evil.example.com", "User-Agent": "Mozilla/5.0"
        })
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            credentials = str(resp.headers.get("Access-Control-Allow-Credentials", "")).lower() == "true"
            reflected_origin = acao == "https://evil.example.com"
            misconfigured = acao == "*" or reflected_origin
            status = (
                VerificationStatus.CONFIRMED
                if reflected_origin and credentials
                else VerificationStatus.STRONGLY_INDICATED
                if misconfigured
                else VerificationStatus.NOT_REPRODUCED
            )
            return verification_result(
                status,
                "Repeat from a researcher-controlled origin in a browser and confirm whether authenticated response data is readable.",
                acao=acao,
                allow_credentials=credentials,
                origin_reflected=reflected_origin,
                misconfigured=misconfigured,
            )
    except Exception as e:
        return verification_result(
            VerificationStatus.NEEDS_MANUAL_FOLLOWUP,
            "Repeat the CORS request manually and preserve both preflight and response headers.",
            error=str(e),
            misconfigured=False,
        )


def _request_headers(url: str, scope: ScopeValidator, method: str = "HEAD", extra_headers: dict | None = None) -> dict:
    import ssl
    import urllib.error
    import urllib.request

    scope.assert_in_scope(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {"User-Agent": "Mozilla/5.0"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            return {"url": url, "status_code": resp.status, "headers": dict(resp.headers)}
    except urllib.error.HTTPError as exc:
        return {"url": url, "status_code": exc.code, "headers": dict(exc.headers or {}), "error": str(exc)}
    except Exception as exc:
        return {"url": url, "error": str(exc), "headers": {}}


def _test_exposed_path(base_url: str, finding: dict, scope: ScopeValidator) -> dict:
    import urllib.parse

    raw_path = str(finding.get("affected") or "").strip()
    if not raw_path:
        m = re.search(r"exposed path\s+(.+)$", finding.get("title", ""), re.IGNORECASE)
        raw_path = m.group(1).strip() if m else ""
    if not raw_path:
        return verification_result(
            VerificationStatus.SKIPPED,
            "Identify the exact in-scope path from recon evidence before attempting protected endpoint confirmation.",
            error="no path to verify",
            confirmed=False,
        )

    if raw_path.startswith("http://") or raw_path.startswith("https://"):
        full_url = raw_path
        path = urllib.parse.urlparse(raw_path).path or "/"
    else:
        path = raw_path if raw_path.startswith("/") else f"/{raw_path}"
        full_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

    result = _request_headers(full_url, scope, method="HEAD")
    if result.get("status_code") == 405 or not result.get("status_code"):
        result = _request_headers(full_url, scope, method="GET")

    status = result.get("status_code", 0) or 0
    confirmed = status in {200, 401, 403}
    return verification_result(
        VerificationStatus.CONFIRMED if confirmed else VerificationStatus.NOT_REPRODUCED,
        "Review the endpoint manually while unauthenticated and with an authorized test account; do not attempt credentials.",
        path=path,
        url=full_url,
        status_code=status,
        confirmed=confirmed,
        manual_verification_needed=not confirmed,
        error=result.get("error", ""),
    )


def _test_missing_security_headers(base_url: str, finding: dict, scope: ScopeValidator) -> dict:
    expected = []
    desc = str(finding.get("description", ""))
    if ":" in desc:
        expected = [h.strip() for h in desc.split(":", 1)[1].split(",") if h.strip()]
    if not expected:
        expected = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]

    result = _request_headers(base_url, scope, method="HEAD")
    if result.get("status_code") == 405 or not result.get("status_code"):
        result = _request_headers(base_url, scope, method="GET")

    headers = result.get("headers", {})
    missing = [header for header in expected if not headers.get(header)]
    return verification_result(
        VerificationStatus.CONFIRMED if missing else VerificationStatus.NOT_REPRODUCED,
        "Confirm header behavior across authenticated pages, error responses, and state-changing routes.",
        url=base_url,
        status_code=result.get("status_code", 0) or 0,
        missing_headers_confirmed=missing,
        confirmed=bool(missing),
        error=result.get("error", ""),
    )
