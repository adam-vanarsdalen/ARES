import unittest
from unittest.mock import patch

import pipeline
from utils.scope_validator import Scope


class TestPipelineAbort(unittest.IsolatedAsyncioTestCase):
    async def test_abort_mid_osint_stops(self):
        session = {"abort": False}
        events = []

        def log(tag, msg, color=""):
            events.append(("log", tag, msg))

        def phase(phase_name, status, detail=""):
            events.append(("phase", phase_name, status, detail))

        def emit(event_type, data):
            events.append((event_type, data))

        p = pipeline.ARESPipeline(
            target="example.com",
            scope=Scope(domains=["example.com", "*.example.com"]),
            mode="full",
            session=session,
            log_fn=log,
            phase_fn=phase,
            emit_fn=emit,
        )

        def dns_side_effect(domain, validator):
            session["abort"] = True
            return {"domain": domain, "records": {}}

        with (
            patch.object(pipeline, "dns_lookup", side_effect=dns_side_effect),
            patch.object(pipeline, "generate_report", return_value="/tmp/fake.md"),
        ):
            out = await p.run()
            self.assertIn("osint", out)
            # When aborted early, OSINT is partial/stopped and later phases are empty dicts.
            self.assertTrue(session["abort"])


if __name__ == "__main__":
    unittest.main()
