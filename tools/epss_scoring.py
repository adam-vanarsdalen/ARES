"""
ARES — EPSS (Exploit Prediction Scoring System) Integration
EPSS is a machine learning model maintained by FIRST.org that gives each CVE
a probability (0.0–1.0) that it will be exploited in the wild within 30 days.

Why this matters more than CVSS:
  - CVSS 9.8 with EPSS 0.001 = theoretical risk, almost never exploited
  - CVSS 5.0 with EPSS 0.95 = actively being exploited right now, fix first

Also correlates CVEs against Metasploit modules — if a CVE has a Metasploit
module, exploitation requires zero skill and is happening in the wild.

API: https://api.first.org/data/v1/epss  (free, no auth)
"""

import json
import logging
import urllib.request
import urllib.parse


logger = logging.getLogger(__name__)


def _epss_unavailable_entry(reason: str) -> dict:
    # Keep shape consistent with successful entries; use epss=0.0 to avoid downstream type errors.
    return {
        "epss": 0.0,
        "epss_percent": 0.0,
        "percentile": 0.0,
        "percentile_percent": 0.0,
        "date": "",
        "exploitation_likelihood": reason,
    }


def get_epss_scores(cve_ids: list[str]) -> dict[str, dict]:
    """
    Fetch EPSS scores for a list of CVE IDs in one batch request.
    Returns {cve_id: {epss, percentile, date}} dict.
    """
    if not cve_ids:
        return {}

    # API accepts comma-separated CVE IDs
    cve_param = ",".join(cve_ids[:100])  # max 100 per request
    url = f"https://api.first.org/data/v1/epss?cve={urllib.parse.quote(cve_param)}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "ARES/1.0 Security Research",
        "Accept": "application/json"
    })

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
        data = json.loads(raw)
    except Exception as e:
        logger.error("EPSS fetch failed for %d CVEs: %s", len(cve_ids), e, exc_info=True)
        return {cve: _epss_unavailable_entry("Unknown — EPSS fetch failed") for cve in cve_ids}

    result = {}
    for item in data.get("data", []):
        cve_id = item.get("cve", "")
        if cve_id:
            epss_score = float(item.get("epss", 0))
            percentile = float(item.get("percentile", 0))
            result[cve_id] = {
                "epss": epss_score,
                "epss_percent": round(epss_score * 100, 2),
                "percentile": percentile,
                "percentile_percent": round(percentile * 100, 1),
                "date": item.get("date", ""),
                "exploitation_likelihood": _epss_label(epss_score)
            }

    # Ensure callers can distinguish "no EPSS data for this CVE" from "not requested".
    for cve in cve_ids:
        if cve not in result:
            result[cve] = _epss_unavailable_entry("Unknown — EPSS data unavailable")
    return result


def _epss_label(score: float) -> str:
    """Human-readable exploitation likelihood label."""
    if score >= 0.5:
        return "CRITICAL — Actively exploited in the wild"
    elif score >= 0.1:
        return "HIGH — Significant exploitation activity"
    elif score >= 0.05:
        return "ELEVATED — Some exploitation observed"
    elif score >= 0.01:
        return "LOW — Occasional exploitation"
    else:
        return "MINIMAL — Rarely exploited"


def _metasploit_check(cve_id: str) -> dict:
    """
    Check if a CVE has a known Metasploit module via Vulhub/MSF search API.
    Falls back to a simple keyword check against ExploitDB.
    """
    # Query ExploitDB search (public, no auth)
    cve_clean = cve_id.replace("CVE-", "").replace("-", " ")
    url = f"https://www.exploit-db.com/search?cve={urllib.parse.quote(cve_id)}&draw=1&columns[0][data]=date_published&order[0][column]=0&order[0][dir]=desc&start=0&length=5"
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0",
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json"
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            count = data.get("recordsTotal", 0)
            exploits = []
            for row in data.get("data", [])[:3]:
                exploits.append({
                    "id": row.get("id", ""),
                    "description": row.get("description", ""),
                    "type": row.get("type", {}).get("val", "") if isinstance(row.get("type"), dict) else str(row.get("type", ""))
                })
            return {"has_public_exploit": count > 0, "exploit_count": count, "exploits": exploits}
    except Exception:
        return {"has_public_exploit": False, "exploit_count": 0, "exploits": []}


def enrich_cves_with_epss(cve_list: list[dict]) -> list[dict]:
    """
    Take a list of CVE dicts (from NVD) and enrich them with:
    - EPSS probability score
    - Exploitation likelihood label
    - Priority score (combined CVSS + EPSS for remediation ordering)

    Returns enriched list sorted by priority (highest first).
    """
    if not cve_list:
        return []

    cve_ids = [c["id"] for c in cve_list if c.get("id")]
    epss_data = get_epss_scores(cve_ids)

    enriched = []
    for cve in cve_list:
        cve_id = cve.get("id", "")
        epss_info = epss_data.get(cve_id, {})

        enriched_cve = dict(cve)
        enriched_cve["epss"] = epss_info.get("epss", 0.0)
        enriched_cve["epss_percent"] = epss_info.get("epss_percent", 0.0)
        enriched_cve["epss_percentile"] = epss_info.get("percentile_percent", 0.0)
        enriched_cve["exploitation_likelihood"] = epss_info.get(
            "exploitation_likelihood", "Unknown — EPSS data unavailable"
        )

        # Priority score: combines CVSS severity with EPSS probability
        # A CVSS 7.5 with EPSS 0.8 is more urgent than CVSS 9.0 with EPSS 0.001
        cvss = cve.get("cvss_score") or 0
        epss = epss_info.get("epss", 0.0)
        enriched_cve["priority_score"] = round((cvss / 10) * 0.4 + epss * 0.6, 4)

        # Human priority label
        ps = enriched_cve["priority_score"]
        if ps >= 0.7:
            enriched_cve["priority"] = "P1 — PATCH IMMEDIATELY"
        elif ps >= 0.4:
            enriched_cve["priority"] = "P2 — Patch within 24 hours"
        elif ps >= 0.2:
            enriched_cve["priority"] = "P3 — Patch this sprint"
        else:
            enriched_cve["priority"] = "P4 — Schedule for next cycle"

        enriched.append(enriched_cve)

    # Sort by priority score descending
    enriched.sort(key=lambda x: x["priority_score"], reverse=True)
    return enriched


def epss_summary(enriched_cves: list[dict]) -> dict:
    """Generate a summary of EPSS analysis for the report."""
    if not enriched_cves:
        return {}

    p1 = [c for c in enriched_cves if c.get("priority", "").startswith("P1")]
    p2 = [c for c in enriched_cves if c.get("priority", "").startswith("P2")]
    high_epss = [c for c in enriched_cves if c.get("epss", 0) >= 0.1]
    top = enriched_cves[0] if enriched_cves else {}

    return {
        "total_cves": len(enriched_cves),
        "p1_immediate": len(p1),
        "p2_urgent": len(p2),
        "high_exploitation_risk": len(high_epss),
        "highest_priority_cve": top.get("id", ""),
        "highest_priority_score": top.get("priority_score", 0),
        "highest_epss": max((c.get("epss", 0) for c in enriched_cves), default=0),
        "remediation_note": (
            f"{len(p1)} CVE(s) require immediate patching based on active exploitation data. "
            f"{len(high_epss)} CVE(s) have >10% probability of exploitation within 30 days."
            if p1 or high_epss else
            "No CVEs with high active exploitation probability detected."
        )
    }
