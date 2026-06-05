"""
ARES canonical evidence and prioritization helpers.

These helpers preserve raw observations, coverage state, and normalized
finding metadata so reports do not collapse collection uncertainty into
false certainty.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone


def _stable_id(kind: str, *parts: object) -> str:
    material = "\x1f".join([kind, *[str(p) for p in parts]])
    return f"{kind}:{hashlib.sha1(material.encode('utf-8', errors='ignore')).hexdigest()[:12]}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_asset(asset_type: str, name: str, value: str = "", confidence: str = "HIGH", **attributes) -> dict:
    asset_id = _stable_id("asset", asset_type, name, value)
    data = {
        "asset_id": asset_id,
        "asset_type": asset_type,
        "name": name,
        "value": value or name,
        "confidence": confidence,
    }
    if attributes:
        data["attributes"] = {k: v for k, v in attributes.items() if v not in (None, "", [], {})}
    return data


def make_evidence(source: str, category: str, summary: str, confidence: str = "MEDIUM", **details) -> dict:
    evidence = {
        "evidence_id": _stable_id("evidence", source, category, summary),
        "source": source,
        "category": category,
        "summary": summary,
        "confidence": confidence,
        "observed_at": utc_now_iso(),
    }
    if details:
        evidence["details"] = {k: v for k, v in details.items() if v not in (None, "", [], {})}
    return evidence


def make_coverage(phase: str, check: str, status: str, details: str = "", **metadata) -> dict:
    item = {
        "phase": phase,
        "check": check,
        "status": status,
    }
    if details:
        item["details"] = details
    if metadata:
        item["metadata"] = {k: v for k, v in metadata.items() if v not in (None, "", [], {})}
    return item


def dedupe_by_key(items: list[dict], key_fields: tuple[str, ...]) -> list[dict]:
    out = []
    seen = set()
    for item in items:
        key = tuple(item.get(field) for field in key_fields)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def severity_to_priority(severity: str, cvss_score: float | int | None = None, epss: float | None = None, confidence: str = "MEDIUM") -> str:
    score = float(cvss_score or 0)
    sev = (severity or "").upper()
    conf = (confidence or "MEDIUM").upper()

    if sev == "CRITICAL" or score >= 9.0 or (epss or 0) >= 0.10:
        return "P1"
    if sev == "HIGH" or score >= 7.0:
        return "P2" if conf in ("HIGH", "MEDIUM") else "P3"
    if sev == "MEDIUM" or score >= 4.0:
        return "P3"
    return "P4"


def enrich_finding(
    finding: dict,
    severity: str,
    evidence_refs: list[str] | None = None,
    confidence: str = "MEDIUM",
    exploitability: str = "MEDIUM",
    business_impact: str = "MEDIUM",
) -> dict:
    item = dict(finding)
    item["severity"] = severity
    item["confidence"] = confidence
    item["exploitability"] = exploitability
    item["business_impact"] = business_impact
    item["priority"] = severity_to_priority(
        severity=severity,
        cvss_score=item.get("cvss_score"),
        epss=item.get("epss"),
        confidence=confidence,
    )
    if evidence_refs:
        item["evidence_refs"] = evidence_refs
    return item


def merge_subdomains(*collections: object) -> list[dict]:
    merged: list[dict] = []
    seen = set()
    for collection in collections:
        if not collection:
            continue
        if isinstance(collection, dict):
            collection = collection.get("discovered_subdomains") or collection.get("live_subdomains") or collection.get("interesting_subdomains") or []
        for item in collection:
            if isinstance(item, dict):
                subdomain = item.get("subdomain") or item.get("name")
                ip = item.get("ip", "")
            else:
                subdomain = str(item)
                ip = ""
            if not subdomain:
                continue
            key = (subdomain, ip)
            if key in seen:
                continue
            seen.add(key)
            merged.append({"subdomain": subdomain, "ip": ip})
    return merged
