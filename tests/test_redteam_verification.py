import unittest
from unittest.mock import patch

import pipeline
import tools.redteam_verification as rv
from utils.scope_validator import Scope


class _Resp:
    def __init__(self, status=200, headers=None):
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _Graph:
    nodes = ["target"]

    def get_critical_paths(self):
        return []

    def to_dict(self):
        return {"nodes": []}


async def _fast_sleep(*args, **kwargs):
    return None


class TestRedteamVerifiers(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(domains=["example.com", "*.example.com"])
        self.validator = pipeline.ScopeValidator(self.scope)  # type: ignore[attr-defined]

    def test_exposed_path_verifier_confirms_accessible_panel(self):
        with patch("urllib.request.urlopen", return_value=_Resp(status=403)):
            result = pipeline._test_exposed_path(  # type: ignore[attr-defined]
                "https://example.com",
                {"title": "Exposed path /admin", "affected": "/admin", "cvss_score": 7.5},
                self.validator,
            )

        self.assertTrue(result["confirmed"])
        self.assertEqual(result["status_code"], 403)
        self.assertEqual(result["path"], "/admin")

    def test_missing_header_verifier_confirms_expected_gaps(self):
        with patch("urllib.request.urlopen", return_value=_Resp(status=200, headers={"X-Frame-Options": "DENY"})):
            result = pipeline._test_missing_security_headers(  # type: ignore[attr-defined]
                "https://example.com",
                {"title": "Missing Security Headers", "description": "Missing headers: Content-Security-Policy, X-Frame-Options"},
                self.validator,
            )

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["missing_headers_confirmed"], ["Content-Security-Policy"])
        self.assertTrue(result["confirmed"])

    def test_grounded_redteam_promotes_verified_results(self):
        red = pipeline._ground_redteam_report(  # type: ignore[attr-defined]
            target="example.com",
            vulns={
                "cve_matches": [],
                "critical_findings": [],
                "high_findings": [{"title": "Exposed path /admin", "description": "Observed HTTP status 200", "cvss_score": 7.5, "affected": "/admin"}],
                "medium_findings": [{"title": "Missing Security Headers", "description": "Missing headers: Content-Security-Policy", "cvss_score": 5.0, "affected": "Web application responses"}],
                "coverage_gaps": [],
            },
            test_results=[
                {"test": "exposed_path", "finding": "Exposed path /admin", "result": {"path": "/admin", "url": "https://example.com/admin", "status_code": 403, "confirmed": True}},
                {"test": "missing_security_headers", "finding": "Missing Security Headers", "result": {"url": "https://example.com", "status_code": 200, "missing_headers_confirmed": ["Content-Security-Policy"], "confirmed": True}},
            ],
            kill_chain_data={"kill_chains": []},
            report={"confirmed_vulnerabilities": [], "proof_of_concepts": [], "recommendations": []},
        )

        confirmed_names = [item["name"] for item in red["confirmed_vulnerabilities"]]
        self.assertIn("Exposed path /admin", confirmed_names)
        self.assertIn("Missing Security Headers", confirmed_names)
        self.assertGreaterEqual(len(red["proof_of_concepts"]), 2)

    def test_open_redirect_confirms_only_reflected_location(self):
        calls = []

        def fake_request(url, method="GET", headers=None, timeout=8):
            calls.append(url)
            if "next=" in url:
                return {"status_code": 302, "headers": {"Location": "https://example.invalid/ares-open-redirect"}, "body_preview": ""}
            return {"status_code": 302, "headers": {"Location": "https://example.com/"}, "body_preview": ""}

        with patch.object(rv, "_request", side_effect=fake_request):
            result = rv.test_open_redirect("https://example.com/login", self.validator)

        self.assertTrue(result["confirmed"])
        self.assertIn("example.invalid", result["location"])
        self.assertEqual(len(calls), 1)

    def test_http_methods_flags_trace_and_skips_put_delete_by_default(self):
        def fake_request(url, method="GET", headers=None, timeout=8):
            return {"status_code": 200 if method == "TRACE" else 204, "headers": {"Allow": "GET,POST,OPTIONS,TRACE"}, "body_preview": ""}

        with patch.object(rv, "_request", side_effect=fake_request):
            result = rv.test_http_methods("https://example.com", self.validator)

        self.assertIn("TRACE", result["methods"])
        self.assertEqual(result["skipped_methods"], ["PUT", "DELETE"])
        self.assertEqual(result["findings"][0]["type"], "trace_enabled")

    def test_clickjacking_confirms_when_frame_protections_absent(self):
        with patch.object(rv, "_request", return_value={"status_code": 200, "headers": {}, "body_preview": ""}):
            result = rv.test_clickjacking("https://example.com", self.validator)

        self.assertTrue(result["confirmed"])

    def test_api_endpoint_401_counts_as_discovered(self):
        def fake_request(url, method="GET", headers=None, timeout=8):
            return {"status_code": 401 if url.endswith("/api") else 404, "headers": {}, "body_preview": ""}

        with patch.object(rv, "_request", side_effect=fake_request):
            result = rv.enumerate_api_endpoints("https://example.com", self.validator)

        self.assertEqual(result["discovered"][0]["path"], "/api")
        self.assertEqual(result["discovered"][0]["status_code"], 401)

    def test_host_header_body_reflection_requires_manual_verification(self):
        with patch.object(rv, "_request", return_value={"status_code": 200, "headers": {}, "body_preview": "evil.example.invalid"}):
            result = rv.test_host_header_injection("https://example.com", self.validator)

        self.assertTrue(result["reflected"])
        self.assertTrue(result["manual_verification_needed"])


class TestRunRedteamRouting(unittest.IsolatedAsyncioTestCase):
    async def test_run_redteam_routes_exposed_path_and_header_checks(self):
        captured = {}
        events = []

        def log(tag, msg, color=""):
            events.append(("log", tag, msg))

        def phase(name, status, detail=""):
            events.append(("phase", name, status, detail))

        def emit(event_type, data):
            events.append((event_type, data))

        p = pipeline.ARESPipeline(
            target="example.com",
            scope=Scope(domains=["example.com", "*.example.com"]),
            mode="full",
            session={},
            log_fn=log,
            phase_fn=phase,
            emit_fn=emit,
        )

        async def fake_synthesis(self, target, vulns, test_results, kill_chain_data):
            captured["test_results"] = test_results
            return {"overall_risk": "MEDIUM", "confirmed_vulnerabilities": [], "proof_of_concepts": [], "kill_chains": [], "recommendations": []}

        vuln_data = {
            "critical_findings": [],
            "high_findings": [{"title": "Exposed path /admin", "description": "Observed HTTP status 200", "cvss_score": 7.5, "affected": "/admin"}],
            "medium_findings": [{"title": "Missing Security Headers", "description": "Missing headers: Content-Security-Policy", "cvss_score": 5.0, "affected": "Web application responses"}],
        }
        osint_data = {"_ct_data": {}, "_js_data": {}}

        with (
            patch.object(pipeline, "_test_exposed_path", return_value={"confirmed": True, "path": "/admin", "url": "https://example.com/admin", "status_code": 403}),
            patch.object(pipeline, "_test_missing_security_headers", return_value={"confirmed": True, "url": "https://example.com", "status_code": 200, "missing_headers_confirmed": ["Content-Security-Policy"]}),
            patch.object(pipeline, "build_attack_graph", return_value=_Graph()),
            patch.object(pipeline, "generate_kill_chains", return_value={"kill_chains": [], "worst_case_scenario": "", "overall_chain_risk": "LOW"}),
            patch.object(pipeline.ARESPipeline, "_ai_redteam_synthesis", new=fake_synthesis),
            patch.object(pipeline.asyncio, "sleep", new=_fast_sleep),
        ):
            await p._run_redteam(vuln_data, osint_data)

        tests = {item["test"] for item in captured["test_results"]}
        self.assertIn("exposed_path", tests)
        self.assertIn("missing_security_headers", tests)

    async def test_run_redteam_honors_verification_cap(self):
        captured = {}
        events = []

        def log(tag, msg, color=""):
            events.append(("log", tag, msg))

        p = pipeline.ARESPipeline(
            target="example.com",
            scope=Scope(domains=["example.com", "*.example.com"]),
            mode="full",
            session={},
            log_fn=log,
            phase_fn=lambda *args: None,
            emit_fn=lambda *args: None,
        )

        async def fake_synthesis(self, target, vulns, test_results, kill_chain_data):
            captured["test_results"] = test_results
            return {"overall_risk": "MEDIUM", "confirmed_vulnerabilities": [], "proof_of_concepts": [], "kill_chains": [], "recommendations": []}

        vuln_data = {
            "critical_findings": [],
            "high_findings": [{"title": f"Clickjacking finding {idx}", "description": "", "cvss_score": 7.0, "affected": "https://example.com"} for idx in range(5)],
            "medium_findings": [],
        }

        with (
            patch.object(pipeline, "REDTEAM_MAX_VERIFICATIONS", 2),
            patch.object(pipeline, "test_clickjacking", return_value={"confirmed": True, "status_code": 200}),
            patch.object(pipeline, "build_attack_graph", return_value=_Graph()),
            patch.object(pipeline, "generate_kill_chains", return_value={"kill_chains": [], "worst_case_scenario": "", "overall_chain_risk": "LOW"}),
            patch.object(pipeline.ARESPipeline, "_ai_redteam_synthesis", new=fake_synthesis),
            patch.object(pipeline.asyncio, "sleep", new=_fast_sleep),
        ):
            await p._run_redteam(vuln_data, {"_ct_data": {}, "_js_data": {}})

        self.assertEqual(len(captured["test_results"]), 2)


if __name__ == "__main__":
    unittest.main()
