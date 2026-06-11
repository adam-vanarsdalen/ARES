from __future__ import annotations

import hashlib

from utils.evidence_ledger import redact_evidence_preview


def stable_id(namespace: str, value: str) -> str:
    return f"{namespace}--{hashlib.sha256(value.encode()).hexdigest()[:32]}"


def all_findings(vuln_report: dict) -> list[dict]:
    return [
        finding
        for bucket in ("critical_findings", "high_findings", "medium_findings")
        for finding in vuln_report.get(bucket, [])
    ]


def sanitize_export(value):
    if isinstance(value, dict):
        return {
            key: sanitize_export(item)
            for key, item in value.items()
            if key.lower() not in {"raw", "raw_secret", "secret_value", "secret_access_key", "session_token", "password"}
        }
    if isinstance(value, list):
        return [sanitize_export(item) for item in value]
    if isinstance(value, str):
        return redact_evidence_preview(value, max_chars=10000)
    return value


def evidence_refs(finding: dict) -> list[str]:
    return list(finding.get("evidence_refs", []))


def manifest_metadata(run_manifest: dict) -> dict:
    return sanitize_export({
        "run_manifest": run_manifest,
        "audit_chain_head": run_manifest.get("audit_chain_head", ""),
    })
