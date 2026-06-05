"""CVE enrichment sources: NVD, OSV, and optional Vulners."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from utils.config import (
    CVE_CACHE_TTL,
    ENABLE_VULNERS,
    NVD_API_KEY,
    NVD_MIN_DELAY,
    VULNERS_API_KEY,
)


_NVD_CACHE: dict[str, tuple[float, dict]] = {}
_LAST_NVD_REQUEST = 0.0
PACKAGE_ECOSYSTEMS = {"npm", "pypi", "maven", "go", "rubygems", "nuget", "crates.io", "cargo"}


def _nvd_url(query: str) -> str:
    query = query.strip()
    if query.startswith("cpe:2.3:"):
        return "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=" + urllib.parse.quote(query) + "&resultsPerPage=10"
    parts = query.split(":")
    if len(parts) >= 3:
        full_cpe = f"cpe:2.3:a:{query}"
        return "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=" + urllib.parse.quote(full_cpe) + "&resultsPerPage=10"
    return "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" + urllib.parse.quote(query.replace(":", " ")) + "&resultsPerPage=5"


def _normalize_nvd(data: dict, query: str) -> dict:
    vulns = []
    for item in data.get("vulnerabilities", [])[:10]:
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        score, severity = None, "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                metric = metrics[key][0]
                score = metric.get("cvssData", {}).get("baseScore")
                severity = metric.get("cvssData", {}).get("baseSeverity") or metric.get("baseSeverity", "UNKNOWN")
                break
        vulns.append({
            "id": cve.get("id"),
            "description": cve.get("descriptions", [{}])[0].get("value", "")[:250],
            "cvss_score": score,
            "severity": severity,
            "published": cve.get("published", "")[:10],
            "source": "nvd",
        })
    return {"cpe": query, "query": query, "vulnerabilities": vulns, "total": data.get("totalResults", 0), "coverage": {"nvd": "success"}}


def fetch_nvd_cves(cpe_or_keyword: str) -> dict:
    query = (cpe_or_keyword or "").strip()
    now = time.time()
    cached = _NVD_CACHE.get(query)
    if cached and now - cached[0] <= CVE_CACHE_TTL:
        out = dict(cached[1])
        out["cache_hit"] = True
        return out

    global _LAST_NVD_REQUEST
    delay = max(0.0, NVD_MIN_DELAY - (now - _LAST_NVD_REQUEST))
    if delay > 0:
        time.sleep(delay)
    _LAST_NVD_REQUEST = time.time()

    headers = {"User-Agent": "ARES/1.0", "Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    req = urllib.request.Request(_nvd_url(query), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        error = f"http_{exc.code}"
        status = "rate_limited" if exc.code == 429 else "failed"
        return {"cpe": query, "query": query, "vulnerabilities": [], "total": 0, "error": error, "coverage": {"nvd": status}}
    except Exception as exc:
        return {"cpe": query, "query": query, "vulnerabilities": [], "total": 0, "error": type(exc).__name__, "coverage": {"nvd": "failed"}}

    out = _normalize_nvd(data, query)
    _NVD_CACHE[query] = (time.time(), out)
    return out


def fetch_osv_vulns(package_name: str, ecosystem: str = "", version: str = "") -> dict:
    ecosystem = ecosystem or ""
    payload = {"package": {"name": package_name}}
    if ecosystem:
        payload["package"]["ecosystem"] = ecosystem
    if version:
        payload["version"] = version
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps(payload).encode("utf-8"),
        headers={"User-Agent": "ARES/1.0", "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except Exception as exc:
        return {"query": package_name, "vulnerabilities": [], "total": 0, "error": type(exc).__name__, "coverage": {"osv": "failed"}}

    vulns = []
    for item in data.get("vulns", [])[:20]:
        aliases = item.get("aliases", []) or []
        vulns.append({
            "id": item.get("id"),
            "aliases": aliases,
            "cve_ids": [alias for alias in aliases if str(alias).startswith("CVE-")],
            "summary": item.get("summary", ""),
            "description": item.get("summary", "")[:250],
            "severity": (item.get("database_specific", {}) or {}).get("severity", "UNKNOWN"),
            "source": "osv",
        })
    return {"query": package_name, "vulnerabilities": vulns, "total": len(vulns), "coverage": {"osv": "success"}}


def fetch_vulners_lucene(query: str) -> dict:
    if not ENABLE_VULNERS or not VULNERS_API_KEY:
        return {"query": query, "vulnerabilities": [], "total": 0, "status": "skipped", "coverage": {"vulners": "skipped"}}
    req = urllib.request.Request(
        "https://vulners.com/api/v3/search/lucene/",
        data=json.dumps({"query": query, "size": 10, "apiKey": VULNERS_API_KEY}).encode("utf-8"),
        headers={"User-Agent": "ARES/1.0", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return {"query": query, "vulnerabilities": [], "total": 0, "error": f"http_{exc.code}", "coverage": {"vulners": "rate_limited" if exc.code == 429 else "failed"}}
    except Exception as exc:
        return {"query": query, "vulnerabilities": [], "total": 0, "error": type(exc).__name__, "coverage": {"vulners": "failed"}}

    docs = data.get("data", {}).get("search", []) if isinstance(data.get("data"), dict) else []
    vulns = []
    for item in docs[:10]:
        src = item.get("_source", {})
        vulns.append({"id": src.get("id") or item.get("_id"), "description": src.get("description", "")[:250], "severity": src.get("cvss", {}).get("severity", "UNKNOWN"), "source": "vulners"})
    return {"query": query, "vulnerabilities": vulns, "total": len(vulns), "coverage": {"vulners": "success"}}


def _package_query(query: str) -> tuple[str, str, str] | None:
    parts = (query or "").split(":")
    if len(parts) >= 2 and parts[0].lower() in PACKAGE_ECOSYSTEMS:
        version = parts[2] if len(parts) > 2 else ""
        return parts[1], parts[0], version
    return None


def _dedupe(vulns: list[dict]) -> list[dict]:
    out = []
    seen = set()
    for item in vulns:
        ids = [*item.get("cve_ids", []), *[alias for alias in item.get("aliases", []) if str(alias).startswith("CVE-")], item.get("id"), *item.get("aliases", [])]
        key = next((value for value in ids if value), item.get("description", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def fetch_cve_data(query: str) -> dict:
    nvd = fetch_nvd_cves(query)
    coverage = dict(nvd.get("coverage", {}))
    vulns = list(nvd.get("vulnerabilities", []))

    pkg = _package_query(query)
    if pkg:
        package_name, ecosystem, version = pkg
        osv = fetch_osv_vulns(package_name, ecosystem, version)
        coverage.update(osv.get("coverage", {}))
        vulns.extend(osv.get("vulnerabilities", []))
    else:
        coverage["osv"] = "skipped"

    if nvd.get("error"):
        vulners = fetch_vulners_lucene(query)
        coverage.update(vulners.get("coverage", {}))
        vulns.extend(vulners.get("vulnerabilities", []))
    else:
        coverage["vulners"] = "skipped"

    vulns = _dedupe(vulns)
    return {
        "cpe": query,
        "query": query,
        "vulnerabilities": vulns,
        "total": len(vulns) if vulns else nvd.get("total", 0),
        "error": nvd.get("error", ""),
        "coverage": coverage,
    }
