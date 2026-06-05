"""Redacted chronological replay artifact generation."""

from __future__ import annotations

import json
from pathlib import Path

from utils.evidence_ledger import redact_evidence_preview


def build_replay(
    run_id: str,
    audit_events: list[dict],
    evidence_ledger: list[dict],
    llm_metadata: list[dict] | None = None,
) -> dict:
    timeline = sorted(
        [
            {"kind": "audit", **event}
            for event in audit_events
        ] + [
            {
                "kind": "evidence",
                "timestamp": evidence.get("timestamp", ""),
                "evidence_id": evidence.get("evidence_id", ""),
                "phase": evidence.get("phase", ""),
                "tool_name": evidence.get("tool_name", ""),
                "action_summary": evidence.get("body_preview_redacted", ""),
            }
            for evidence in evidence_ledger
        ],
        key=lambda item: (item.get("timestamp", ""), item.get("event_id", ""), item.get("evidence_id", "")),
    )
    return {
        "run_id": run_id,
        "timeline": timeline,
        "llm_metadata": [
            {
                "model": item.get("model", ""),
                "prompt_hash": item.get("prompt_hash", ""),
                "prompt_version": item.get("prompt_version", ""),
                "input_summary_redacted": redact_evidence_preview(item.get("input_summary_redacted", "")),
                "output_hash": item.get("output_hash", ""),
                "latency_ms": item.get("latency_ms", 0),
                "fallback_used": bool(item.get("fallback_used", False)),
            }
            for item in (llm_metadata or [])
        ],
    }


def write_replay(output_dir: str, replay: dict) -> str:
    path = Path(output_dir) / f"{replay['run_id']}_replay.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(replay, indent=2), encoding="utf-8")
    return str(path)
