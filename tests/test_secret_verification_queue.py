import json
import os
import sys
import tempfile
from unittest.mock import patch

from fastapi.testclient import TestClient

import pipeline
from utils.report_generator import generate_report


RAW_AWS_KEY = "AKIAABCDEFGHIJKLMNOP"
RAW_GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"


def test_secret_verification_queue_never_stores_raw_secret():
    js_data = {
        "url": "https://example.com",
        "page_url": "https://example.com/app.js",
        "secrets": [
            {
                "type": "AWS Access Key",
                "value": RAW_AWS_KEY,
                "source_url": "https://example.com/app.js",
                "full_length": len(RAW_AWS_KEY),
            }
        ],
    }

    queue = pipeline.build_secret_verification_queue(js_data)

    assert len(queue) == 1
    assert queue[0]["raw_secret_stored"] is False
    assert queue[0]["manual_verification"] is True
    assert queue[0]["manual_verification_required"] is True
    assert queue[0]["rotation_recommended"] is True
    assert queue[0]["verification_source"] == "discovered_redacted"
    assert RAW_AWS_KEY not in json.dumps(queue)
    assert "sts:GetCallerIdentity" not in queue[0]["recommended_safe_check"]


def test_sanitized_js_data_removes_raw_secret_before_sse_payload():
    js_data = {
        "secrets": [
            {
                "type": "GitHub Token",
                "value": RAW_GITHUB_TOKEN,
                "source_url": "https://example.com/main.js",
                "severity": "HIGH",
            }
        ]
    }

    safe_js = pipeline._sanitize_js_data(js_data)  # type: ignore[attr-defined]
    import server

    payload = server.format_sse_event("tool_result", {"tool": "js_intelligence", "data": safe_js})
    rendered = json.dumps(payload)

    assert RAW_GITHUB_TOKEN not in rendered
    assert "value" not in safe_js["secrets"][0]
    assert safe_js["secrets"][0]["raw_secret_stored"] is False


def test_full_secret_never_appears_in_markdown_or_json_reports():
    js_data = {
        "url": "https://example.com",
        "page_url": "https://example.com/app.js",
        "endpoints": [],
        "secrets": [
            {
                "type": "Stripe Key",
                "value": "sk_" + "live_" + "abcdefghijklmnopqrstuvwxyz123456",
                "source_url": "https://example.com/app.js",
                "full_length": 39,
            }
        ],
    }
    safe_js = pipeline._sanitize_js_data(js_data)  # type: ignore[attr-defined]
    queue = pipeline.build_secret_verification_queue(safe_js)
    osint = pipeline._ground_osint_report(  # type: ignore[attr-defined]
        target="example.com",
        dns={"resolved_ip": ""},
        whois={"fields": {}},
        subdomains={"discovered_subdomains": []},
        http={"tech_signals": [], "missing_security_headers": []},
        misconfigs={"findings": []},
        ct_data={"total_unique": 0, "interesting_subdomains": []},
        js_data=safe_js,
        report={},
        secret_verification_queue=queue,
    )
    vuln = pipeline._ground_vuln_report(  # type: ignore[attr-defined]
        target="example.com",
        osint={**osint, "_js_data": safe_js, "_secret_verification_queue": queue},
        ports={"open_ports": []},
        cves=[],
        report={},
    )
    red = {"overall_risk": "HIGH", "confirmed_vulnerabilities": [], "proof_of_concepts": [], "recommendations": []}

    with tempfile.TemporaryDirectory() as td:
        path = generate_report("example.com", osint, vuln, red, output_dir=td)
        outputs = [
            path,
            path.replace(".md", ".json"),
            path.replace(".md", ".sarif.json"),
            path.replace(".md", ".cdx.json"),
        ]
        combined = "\n".join(open(item).read() for item in outputs)

    assert "sk_" + "live_" + "abcdefghijklmnopqrstuvwxyz123456" not in combined
    assert all(item["raw_secret_stored"] is False for item in queue)
    assert "needs_manual_verification" in combined


def _reload_server(
    manual_secret_verify: str,
    *,
    profile: str = "recon",
    advanced_enabled: str = "false",
):
    os.environ["ARES_API_KEY"] = "secret-test-key"
    os.environ["ARES_ENV"] = "dev"
    os.environ["ARES_DB_PATH"] = ":memory:"
    os.environ["ARES_ENABLE_MANUAL_SECRET_VERIFY"] = manual_secret_verify
    os.environ["ARES_ENABLE_ADVANCED_VERIFICATION"] = advanced_enabled
    os.environ["ARES_PROFILE"] = profile
    os.environ["ARES_ROE_POLICY_ID"] = "example"
    os.environ["ARES_ROE_POLICY_DIR"] = "policies/roe"
    for mod in list(sys.modules):
        if mod in {"server", "utils.config", "utils.session_store", "utils.roe"}:
            sys.modules.pop(mod, None)
    with patch("ollama_compat.check_ollama", return_value={"running": True, "models": []}):
        import server

        return server, TestClient(server.app)


def test_manual_secret_verify_endpoint_disabled_returns_404():
    _, client = _reload_server("false")
    response = client.post(
        "/manual/verify-secret",
        headers={"X-ARES-Key": "secret-test-key"},
        json={"type": "GitHub Token", "secret_value": RAW_GITHUB_TOKEN},
    )

    assert response.status_code == 404


def test_manual_secret_verify_endpoint_enabled_does_not_persist_or_echo_secret():
    server, client = _reload_server("true", profile="advanced", advanced_enabled="true")
    response = client.post(
        "/manual/verify-secret",
        headers={"X-ARES-Key": "secret-test-key"},
        json={
            "type": "GitHub Token",
            "secret_value": RAW_GITHUB_TOKEN,
            "policy_id": "example",
            "operator_confirmation": True,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "GitHub Token"
    assert body["not_persisted"] is True
    assert body["manual_only"] is True
    assert body["real_provider_calls"] is False
    assert RAW_GITHUB_TOKEN not in json.dumps(body)
    assert server.list_recent_sessions(limit=10) == []


def test_manual_secret_verify_requires_advanced_or_custom_profile():
    _, client = _reload_server("true", profile="recon", advanced_enabled="true")
    response = client.post(
        "/manual/verify-secret",
        headers={"X-ARES-Key": "secret-test-key"},
        json={
            "type": "GitHub Token",
            "provider": "github",
            "profile": "advanced",
            "policy_id": "example",
            "operator_confirmation": True,
            "secret_value": RAW_GITHUB_TOKEN,
        },
    )

    assert response.status_code == 403
    assert RAW_GITHUB_TOKEN not in response.text
