"""Tamper-evident append-only audit event chain."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from utils.evidence_ledger import redact_evidence_preview


@dataclass
class AuditEvent:
    event_id: str
    run_id: str
    timestamp: str
    actor: str
    event_type: str
    phase: str
    tool_name: str
    profile: str
    action_summary: str
    decision: dict
    evidence_id: str = ""
    finding_id: str = ""
    previous_hash: str = ""
    event_hash: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _event_hash(payload: dict) -> str:
    material = {key: value for key, value in payload.items() if key != "event_hash"}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AuditLog:
    def __init__(self, run_id: str, actor: str = "ARES"):
        self.run_id = run_id
        self.actor = actor
        self.events: list[AuditEvent] = []

    @property
    def chain_head(self) -> str:
        return self.events[-1].event_hash if self.events else ""

    def record(
        self,
        event_type: str,
        *,
        phase: str = "",
        tool_name: str = "",
        profile: str = "",
        action_summary: str = "",
        decision: dict | None = None,
        evidence_id: str = "",
        finding_id: str = "",
    ) -> AuditEvent:
        timestamp = datetime.now(timezone.utc).isoformat()
        event = AuditEvent(
            event_id=f"audit-{len(self.events) + 1:06d}",
            run_id=self.run_id,
            timestamp=timestamp,
            actor=self.actor,
            event_type=event_type,
            phase=phase,
            tool_name=tool_name,
            profile=profile,
            action_summary=redact_evidence_preview(action_summary, max_chars=1000),
            decision=decision or {},
            evidence_id=evidence_id,
            finding_id=finding_id,
            previous_hash=self.chain_head,
        )
        event.event_hash = _event_hash(event.to_dict())
        self.events.append(event)
        return event

    def serialize(self) -> list[dict]:
        return [event.to_dict() for event in self.events]


def validate_audit_chain(events: list[dict]) -> bool:
    previous = ""
    for event in events:
        if event.get("previous_hash", "") != previous:
            return False
        if _event_hash(event) != event.get("event_hash"):
            return False
        previous = event.get("event_hash", "")
    return True


def append_audit_event(events: list[dict], run_id: str, event_type: str, **fields) -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    event = {
        "event_id": f"audit-{len(events) + 1:06d}",
        "run_id": run_id,
        "timestamp": timestamp,
        "actor": fields.get("actor", "ARES operator"),
        "event_type": event_type,
        "phase": fields.get("phase", "review"),
        "tool_name": fields.get("tool_name", ""),
        "profile": fields.get("profile", ""),
        "action_summary": redact_evidence_preview(fields.get("action_summary", ""), max_chars=1000),
        "decision": fields.get("decision", {}),
        "evidence_id": fields.get("evidence_id", ""),
        "finding_id": fields.get("finding_id", ""),
        "previous_hash": events[-1].get("event_hash", "") if events else "",
        "event_hash": "",
    }
    event["event_hash"] = _event_hash(event)
    events.append(event)
    return event
