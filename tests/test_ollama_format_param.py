import unittest

import ollama_compat


class TestOllamaFormatParam(unittest.TestCase):
    def test_default_payload_sets_think_false(self):
        captured = {}

        def fake_post(url, payload, timeout_s):
            captured["payload"] = payload
            return {"message": {"content": "hello"}}

        orig = ollama_compat._http_post_json
        try:
            ollama_compat._http_post_json = fake_post  # type: ignore[assignment]
            res = ollama_compat.ollama_chat([{"role": "user", "content": "hi"}])
            self.assertTrue(res["ok"])
            self.assertFalse(captured["payload"].get("think", True))
        finally:
            ollama_compat._http_post_json = orig  # type: ignore[assignment]

    def test_json_mode_sets_format_json(self):
        captured = {}

        def fake_post(url, payload, timeout_s):
            captured["payload"] = payload
            return {"message": {"content": '{"ok": true}'}}

        orig = ollama_compat._http_post_json
        try:
            ollama_compat._http_post_json = fake_post  # type: ignore[assignment]
            res = ollama_compat.ollama_chat([{"role": "user", "content": "hi"}], response_format="json")
            self.assertTrue(res["ok"])
            self.assertEqual(captured["payload"].get("format"), "json")
        finally:
            ollama_compat._http_post_json = orig  # type: ignore[assignment]

    def test_json_mode_sets_schema_object_when_provided(self):
        captured = {}
        schema = {"type": "object", "properties": {"a": {"type": "number"}}, "required": ["a"]}

        def fake_post(url, payload, timeout_s):
            captured["payload"] = payload
            return {"message": {"content": '{"a": 1}'}}

        orig = ollama_compat._http_post_json
        try:
            ollama_compat._http_post_json = fake_post  # type: ignore[assignment]
            res = ollama_compat.ollama_chat(
                [{"role": "user", "content": "hi"}],
                response_format="json",
                json_schema=schema,
            )
            self.assertTrue(res["ok"])
            self.assertEqual(captured["payload"].get("format"), schema)
        finally:
            ollama_compat._http_post_json = orig  # type: ignore[assignment]

    def test_messages_create_honors_explicit_response_format(self):
        captured = {}

        def fake_post(url, payload, timeout_s):
            captured["payload"] = payload
            return {"message": {"content": '{"ok": true}'}}

        orig = ollama_compat._http_post_json
        try:
            ollama_compat._http_post_json = fake_post  # type: ignore[assignment]
            resp = ollama_compat.OllamaClient().messages.create(
                messages=[{"role": "user", "content": "hi"}],
                response_format="json",
            )
            self.assertEqual(resp.stop_reason, "end_turn")
            self.assertEqual(captured["payload"].get("format"), "json")
        finally:
            ollama_compat._http_post_json = orig  # type: ignore[assignment]
