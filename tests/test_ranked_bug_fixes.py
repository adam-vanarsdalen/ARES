import asyncio
import os
import tempfile
import time
import unittest
from unittest.mock import patch

import pipeline
import server
from utils import session_store
from utils.scope_validator import Scope


async def _fast_sleep(*args, **kwargs):
    return None


class TestRankedBugFixes(unittest.TestCase):
    def test_clean_json_extracts_first_object_only(self):
        text = '```json\n{"a": 1}\n```\nextra {"b": 2}'
        self.assertEqual(pipeline._clean_json(text), '{"a": 1}')

    def test_prune_old_sessions_once_removes_expired_terminal_state(self):
        old_ts = time.time() - 7200
        session_store.init_db()
        session_store.delete_session("old")
        session_store.delete_session("new")
        session_store.create_session("old", "old.example", "full", "2026-01-01T00:00:00Z")
        session_store.update_session("old", status="complete", completed_at=old_ts)
        server.event_queues["old"] = asyncio.Queue()
        session_store.create_session("new", "new.example", "full", "2026-01-02T00:00:00Z")
        session_store.update_session("new", status="complete", completed_at=time.time())
        server.event_queues["new"] = asyncio.Queue()
        try:
            server._prune_old_sessions_once(ttl_seconds=3600)
            self.assertIsNone(session_store.get_session("old"))
            self.assertNotIn("old", server.event_queues)
            self.assertIsNotNone(session_store.get_session("new"))
            self.assertIn("new", server.event_queues)
        finally:
            server.event_queues.pop("old", None)
            server.event_queues.pop("new", None)
            session_store.delete_session("new")

    def test_allowed_origins_are_not_wildcard(self):
        self.assertNotIn("*", server._allowed_origins)

    def test_assessment_request_limits_list_lengths(self):
        req = server.AssessmentRequest(target="example.com", domains=["a.com"] * 50, ip_ranges=["10.0.0.0/24"] * 20)
        self.assertEqual(len(req.domains), 50)
        self.assertEqual(len(req.ip_ranges), 20)
        with self.assertRaises(Exception):
            server.AssessmentRequest(target="example.com", domains=["a.com"] * 51)
        with self.assertRaises(Exception):
            server.AssessmentRequest(target="example.com", ip_ranges=["10.0.0.0/24"] * 21)


class TestPriorityOneFlowFixes(unittest.IsolatedAsyncioTestCase):
    async def test_run_recon_does_not_duplicate_js_secret_findings(self):
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

        secret_finding = {
            "title": "Hardcoded API Key in JavaScript",
            "description": "Value preview: ABCD...1234",
            "cvss_score": 7.5,
            "affected": "Client-side JavaScript",
        }
        osint_data = {
            "technology_stack": [],
            "_cpe_strings": [],
            "_js_data": {"secrets": [{"type": "API Key", "value_preview": "ABCD...1234", "severity": "HIGH"}]},
            "_js_endpoints_count": 0,
            "misconfig_count": 0,
            "coverage_gaps": [],
        }

        with (
            patch.object(pipeline, "port_scan", return_value={"open_ports": [], "detected_tech": []}),
            patch.object(pipeline, "probe_version_disclosure", return_value={"base_url": "https://example.com", "paths": [], "findings": [], "coverage": {"paths_total": 18, "exposed": 0, "protected": 0, "absent": 18}}),
            patch.object(pipeline, "tls_audit", return_value={"target": "example.com", "port": 443, "certificate": {}, "protocols": {}, "selected_cipher": "", "findings": [], "coverage": {}}),
            patch.object(pipeline, "map_to_mitre", side_effect=lambda items: items),
            patch.object(pipeline, "fetch_cve_data", return_value={"total": 0, "vulnerabilities": []}),
            patch.object(
                pipeline.ARESPipeline,
                "_ai_vuln_analysis",
                return_value={
                    "critical_findings": [],
                    "high_findings": [secret_finding],
                    "medium_findings": [],
                    "attack_vectors": [],
                    "scan_summary": "",
                    "coverage_gaps": [],
                },
            ),
            patch.object(pipeline.asyncio, "sleep", new=_fast_sleep),
        ):
            out = await p._run_recon(osint_data)

        self.assertEqual(sum(1 for f in out["high_findings"] if f["title"] == secret_finding["title"]), 1)

    async def test_run_pipeline_background_does_not_emit_complete_after_abort(self):
        session_id = "stop-race"
        session_store.init_db()
        session_store.delete_session(session_id)
        session_store.create_session(session_id, "example.com", "full", "now")
        session_store.update_session(
            session_id,
            status="running",
            results={},
            abort=False,
            completed_at=None,
        )
        server.event_queues[session_id] = asyncio.Queue()

        class _FakePipeline:
            def __init__(self, **kwargs):
                self._session = kwargs["session"]

            async def run(self):
                self._session["abort"] = True
                return {"report_path": "/tmp/fake.md", "osint": {"summary": "x"}, "redteam": {"overall_risk": "LOW"}}

        try:
            with patch.object(server, "ARESPipeline", _FakePipeline):
                await server.run_pipeline_background(session_id, "example.com", Scope(domains=["example.com"]), "full")

            self.assertEqual(session_store.get_session(session_id)["status"], "running")
            queued_types = []
            while not server.event_queues[session_id].empty():
                queued_types.append(server.event_queues[session_id].get_nowait()["type"])
            self.assertNotIn("complete", queued_types)
        finally:
            server.event_queues.pop(session_id, None)
            session_store.delete_session(session_id)

    async def test_finalize_uses_absolute_reports_dir(self):
        events = []

        def log(tag, msg, color=""):
            events.append((tag, msg))

        p = pipeline.ARESPipeline(
            target="example.com",
            scope=Scope(domains=["example.com"]),
            mode="full",
            session={},
            log_fn=log,
            phase_fn=lambda *args, **kwargs: None,
            emit_fn=lambda *args, **kwargs: None,
        )

        captured = {}

        with tempfile.TemporaryDirectory() as td:
            def fake_generate_report(**kwargs):
                captured.update(kwargs)
                return os.path.join(td, "report.md")

            with patch.object(pipeline, "generate_report", side_effect=fake_generate_report):
                out = p._finalize({}, {}, {})

        self.assertTrue(os.path.isabs(captured["output_dir"]))
        self.assertEqual(out["report_path"], os.path.join(td, "report.md"))


if __name__ == "__main__":
    unittest.main()
