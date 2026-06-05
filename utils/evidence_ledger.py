"""Redacted evidence ledger and finding reproducibility helpers."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


_SECRET_PATTERNS = (
    re.compile(r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{12,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b"),
    re.compile(r"(?i)\b(authorization|api[_-]?key|token|secret|password)\b\s*[:=]\s*[^\s,;]+"),
)


@dataclass
class EvidenceRecord:
    evidence_id: str
    run_id: str
    finding_id: str = ""
    asset_id: str = ""
    url: str = ""
    method: str = "GET"
    tool_name: str = ""
    phase: str = ""
    profile: str = ""
    timestamp: str = ""
    request_metadata_redacted: dict = field(default_factory=dict)
    response_metadata: dict = field(default_factory=dict)
    status_code: int = 0
    headers_observed: list[str] = field(default_factory=list)
    body_hash: str = ""
    body_preview_redacted: str = ""
    screenshot_hash: str = ""
    scope_decision: dict = field(default_factory=dict)
    roe_decision: dict = field(default_factory=dict)
    capability_decision: dict = field(default_factory=dict)
    redaction_applied: bool = True
    raw_secret_stored: bool = False
    reproduction_hint: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def redact_evidence_preview(value: object, max_chars: int = 500) -> str:
    preview = str(value or "")
    for pattern in _SECRET_PATTERNS:
        preview = pattern.sub("[REDACTED]", preview)
    return preview[:max_chars]


def hash_body(body: object) -> str:
    if isinstance(body, bytes):
        payload = body
    else:
        payload = str(body or "").encode("utf-8", errors="ignore")
    return hashlib.sha256(payload).hexdigest()


def create_evidence_record(
    *,
    run_id: str,
    tool_name: str,
    phase: str,
    profile: str,
    finding_id: str = "",
    asset_id: str = "",
    url: str = "",
    method: str = "GET",
    request_metadata: dict | None = None,
    response_metadata: dict | None = None,
    status_code: int = 0,
    headers_observed: list[str] | None = None,
    body: object = "",
    body_preview: object = "",
    screenshot_hash: str = "",
    scope_decision: dict | None = None,
    roe_decision: dict | None = None,
    capability_decision: dict | None = None,
    reproduction_hint: str = "",
    error: str = "",
) -> EvidenceRecord:
    timestamp = datetime.now(timezone.utc).isoformat()
    material = json.dumps(
        [run_id, finding_id, asset_id, url, method, tool_name, phase, status_code, hash_body(body)],
        sort_keys=True,
    )
    evidence_id = "evidence:" + hashlib.sha256(material.encode()).hexdigest()[:16]
    safe_request = json.loads(redact_evidence_preview(json.dumps(request_metadata or {}), max_chars=100000))
    safe_response = json.loads(redact_evidence_preview(json.dumps(response_metadata or {}), max_chars=100000))
    return EvidenceRecord(
        evidence_id=evidence_id,
        run_id=run_id,
        finding_id=finding_id,
        asset_id=asset_id,
        url=url,
        method=method.upper(),
        tool_name=tool_name,
        phase=phase,
        profile=profile,
        timestamp=timestamp,
        request_metadata_redacted=safe_request,
        response_metadata=safe_response,
        status_code=int(status_code or 0),
        headers_observed=list(headers_observed or []),
        body_hash=hash_body(body),
        body_preview_redacted=redact_evidence_preview(body_preview),
        screenshot_hash=screenshot_hash,
        scope_decision=dict(scope_decision or {}),
        roe_decision=dict(roe_decision or {}),
        capability_decision=dict(capability_decision or {}),
        redaction_applied=True,
        raw_secret_stored=False,
        reproduction_hint=reproduction_hint or "Repeat the named tool against the same in-scope asset and compare redacted response metadata.",
        error=redact_evidence_preview(error),
    )


def attach_evidence_to_finding(finding: dict, evidence: EvidenceRecord | dict) -> dict:
    record = evidence.to_dict() if isinstance(evidence, EvidenceRecord) else evidence
    finding.setdefault("finding_id", "finding:" + hashlib.sha256(
        f"{finding.get('title', '')}|{finding.get('affected', '')}".encode()
    ).hexdigest()[:12])
    refs = finding.setdefault("evidence_refs", [])
    if record["evidence_id"] not in refs:
        refs.append(record["evidence_id"])
    if record.get("reproduction_hint"):
        finding.setdefault("reproduction_steps", build_reproduction_steps(record))
    return finding


def get_evidence_for_finding(ledger: list[dict], finding_id: str) -> list[dict]:
    return [record for record in ledger if record.get("finding_id") == finding_id]


def build_reproduction_steps(evidence: EvidenceRecord | dict) -> list[str]:
    record = evidence.to_dict() if isinstance(evidence, EvidenceRecord) else evidence
    steps = [f"Confirm the target remains in scope: {record.get('url') or 'recorded asset'}."]
    if record.get("tool_name"):
        steps.append(f"Run the non-destructive `{record['tool_name']}` check using `{record.get('method', 'GET')}`.")
    if record.get("reproduction_hint"):
        steps.append(record["reproduction_hint"])
    steps.append(f"Compare the response status and body hash with evidence `{record.get('evidence_id', '')}`.")
    return steps


def serialize_evidence_ledger(records: list[EvidenceRecord | dict]) -> list[dict]:
    serialized = [record.to_dict() if isinstance(record, EvidenceRecord) else dict(record) for record in records]
    return sorted(serialized, key=lambda item: (item.get("timestamp", ""), item.get("evidence_id", "")))


def build_pipeline_evidence_ledger(run_id: str, profile: str, target: str, osint: dict, recon: dict, redteam: dict) -> list[dict]:
    records: list[EvidenceRecord] = []
    phase_data = (("osint", osint), ("recon", recon))
    for phase, data in phase_data:
        for item in data.get("evidence_log", []):
            details = item.get("details", {})
            records.append(create_evidence_record(
                run_id=run_id,
                tool_name=item.get("source", "ares"),
                phase=phase,
                profile=profile,
                url=details.get("url", target),
                status_code=details.get("status_code", 0),
                body=item.get("summary", ""),
                body_preview=item.get("summary", ""),
                reproduction_hint=f"Repeat `{item.get('source', 'ARES')}` and compare the recorded observation.",
            ))

    for severity_key in ("critical_findings", "high_findings", "medium_findings"):
        for finding in recon.get(severity_key, []):
            finding_id = finding.setdefault("finding_id", "finding:" + hashlib.sha256(
                f"{finding.get('title', '')}|{finding.get('affected', '')}".encode()
            ).hexdigest()[:12])
            record = create_evidence_record(
                run_id=run_id,
                finding_id=finding_id,
                tool_name=finding.get("source") or (finding.get("evidence_refs") or ["recon"])[0],
                phase="recon",
                profile=profile,
                url=finding.get("affected", target),
                body=finding.get("description", ""),
                body_preview=finding.get("description", ""),
                reproduction_hint="Repeat the associated evidence source against the affected in-scope asset and validate the described condition.",
            )
            attach_evidence_to_finding(finding, record)
            records.append(record)

    for item in redteam.get("verification_results", []):
        result = item.get("result", {})
        records.append(create_evidence_record(
            run_id=run_id,
            tool_name=item.get("test", "verification"),
            phase="redteam",
            profile=profile,
            url=result.get("url", target),
            method=result.get("method", "GET"),
            status_code=result.get("status_code", 0),
            body=result,
            body_preview=result,
            capability_decision=item.get("authorization", {}),
            reproduction_hint=result.get("next_best_manual_test", ""),
            error=result.get("error", ""),
        ))
    for simulation in redteam.get("lab_simulations", []):
        records.append(create_evidence_record(
            run_id=run_id,
            tool_name="lab_exploit_simulation",
            phase="lab",
            profile=profile,
            url=simulation.get("target", target),
            body=simulation,
            body_preview=simulation.get("impact_narrative", ""),
            reproduction_hint=simulation.get("safe_reproduction", ""),
        ))
    return serialize_evidence_ledger(records)
