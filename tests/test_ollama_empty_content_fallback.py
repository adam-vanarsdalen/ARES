import unittest

import ollama_compat


class TestOllamaEmptyContentFallback(unittest.TestCase):
    def test_schema_format_relaxes_to_json_on_empty(self):
        calls = []

        def fake_post(url, payload, timeout_s):
            calls.append(payload.get("format"))
            if len(calls) == 1:
                return {"message": {"content": ""}}
            return {"message": {"content": '{"a": 1}'}}

        orig = ollama_compat._http_post_json
        try:
            ollama_compat._http_post_json = fake_post  # type: ignore[assignment]
            schema = {"type": "object", "properties": {"a": {"type": "number"}}, "required": ["a"]}
            res = ollama_compat.ollama_chat(
                [{"role": "user", "content": "hi"}],
                response_format="json",
                json_schema=schema,
                timeout_s=5,
                total_timeout_s=5,
                max_retries=2,
            )
            self.assertTrue(res["ok"])
            self.assertEqual(calls[0], schema)
            self.assertEqual(calls[1], "json")
        finally:
            ollama_compat._http_post_json = orig  # type: ignore[assignment]

    def test_json_format_relaxes_to_no_format_on_empty(self):
        calls = []

        def fake_post(url, payload, timeout_s):
            calls.append(payload.get("format", None))
            if len(calls) == 1:
                return {"message": {"content": ""}}
            return {"message": {"content": '{"ok": true}'}}

        orig = ollama_compat._http_post_json
        try:
            ollama_compat._http_post_json = fake_post  # type: ignore[assignment]
            res = ollama_compat.ollama_chat(
                [{"role": "user", "content": "hi"}],
                model="qwen3.5:9b",
                response_format="json",
                timeout_s=5,
                total_timeout_s=5,
                max_retries=2,
            )
            self.assertTrue(res["ok"])
            self.assertEqual(calls[0], "json")
            self.assertIsNone(calls[1])
        finally:
            ollama_compat._http_post_json = orig  # type: ignore[assignment]

    def test_cloud_json_mode_retries_same_format_on_empty(self):
        calls = []

        def fake_post(url, payload, timeout_s):
            calls.append(payload.get("format", None))
            if len(calls) == 1:
                return {"message": {"content": ""}}
            return {"message": {"content": '{"ok": true}'}}

        orig = ollama_compat._http_post_json
        try:
            ollama_compat._http_post_json = fake_post  # type: ignore[assignment]
            res = ollama_compat.ollama_chat(
                [{"role": "user", "content": "hi"}],
                model="qwen3.5:397b-cloud",
                response_format="json",
                timeout_s=5,
                total_timeout_s=5,
                max_retries=2,
            )
            self.assertTrue(res["ok"])
            self.assertEqual(calls, ["json", "json"])
        finally:
            ollama_compat._http_post_json = orig  # type: ignore[assignment]

    def test_surfaces_ollama_error_field(self):
        def fake_post(url, payload, timeout_s):
            return {"error": "model not found"}

        orig = ollama_compat._http_post_json
        try:
            ollama_compat._http_post_json = fake_post  # type: ignore[assignment]
            res = ollama_compat.ollama_chat(
                [{"role": "user", "content": "hi"}],
                response_format="json",
                timeout_s=5,
                total_timeout_s=5,
                max_retries=0,
            )
            self.assertFalse(res["ok"])
            self.assertIn("model not found", res["error"])
        finally:
            ollama_compat._http_post_json = orig  # type: ignore[assignment]
