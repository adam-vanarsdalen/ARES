import json

from utils.audit_log import AuditLog, validate_audit_chain
from utils.observability import otel_status, trace_span
from utils.replay import build_replay, write_replay


def test_audit_hash_chain_validates():
    audit = AuditLog("run-1")
    audit.record("run_started", profile="recon", action_summary="Started")
    audit.record("tool_completed", tool_name="http_probe", action_summary="Completed")
    assert validate_audit_chain(audit.serialize()) is True
    assert audit.chain_head == audit.serialize()[-1]["event_hash"]


def test_audit_tampering_fails_validation():
    audit = AuditLog("run-2")
    audit.record("run_started", action_summary="Started")
    audit.record("action_denied", action_summary="Blocked")
    events = audit.serialize()
    events[0]["action_summary"] = "Tampered"
    assert validate_audit_chain(events) is False


def test_replay_json_is_generated_and_redacted(tmp_path):
    audit = AuditLog("run-3")
    audit.record(
        "tool_completed",
        tool_name="secret_check",
        action_summary="token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
    )
    replay = build_replay(
        "run-3",
        audit.serialize(),
        [{
            "timestamp": "2026-06-05T00:00:00Z",
            "evidence_id": "evidence:1",
            "phase": "verify",
            "tool_name": "secret_check",
            "body_preview_redacted": "[REDACTED]",
        }],
        [{
            "model": "qwen",
            "prompt_hash": "prompt-hash",
            "prompt_version": "v1",
            "input_summary_redacted": "Authorization: Bearer secret-value",
            "output_hash": "output-hash",
            "latency_ms": 12,
            "fallback_used": False,
        }],
    )
    path = write_replay(str(tmp_path), replay)
    rendered = open(path, encoding="utf-8").read()
    assert json.loads(rendered)["run_id"] == "run-3"
    assert "ghp_" not in rendered
    assert "secret-value" not in rendered
    assert replay["timeline"]


def test_otel_disabled_requires_no_extra_dependency():
    status = otel_status()
    assert status["enabled"] is False
    with trace_span("test") as span:
        assert span is None
