import unittest

import ollama_compat


class TestOllamaTotalTimeoutBudget(unittest.TestCase):
    def test_total_timeout_budget_stops_extra_retries(self):
        calls = {"n": 0}

        def fake_post(url, payload, timeout_s):
            calls["n"] += 1
            raise TimeoutError("timed out")

        orig = ollama_compat._http_post_json
        try:
            ollama_compat._http_post_json = fake_post  # type: ignore[assignment]
            res = ollama_compat.ollama_chat(
                [{"role": "user", "content": "hi"}],
                response_format="json",
                timeout_s=30,
                total_timeout_s=0.01,  # budget too small to justify multiple attempts
                max_retries=2,
            )
            self.assertFalse(res["ok"])
            self.assertGreaterEqual(calls["n"], 1)
            self.assertLessEqual(calls["n"], 2)
        finally:
            ollama_compat._http_post_json = orig  # type: ignore[assignment]

