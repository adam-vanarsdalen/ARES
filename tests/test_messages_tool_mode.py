import unittest

import ollama_compat


class TestMessagesToolMode(unittest.TestCase):
    def test_tool_mode_returns_tool_use(self):
        def fake_post(url, payload, timeout_s):
            # Strict JSON tool mode should set response_format=json and include format.
            return {"message": {"content": '{"tool":"dns_lookup","input":{"domain":"example.com"}}'}}

        orig = ollama_compat._http_post_json
        try:
            ollama_compat._http_post_json = fake_post  # type: ignore[assignment]
            resp = ollama_compat.OllamaClient().messages.create(
                model=ollama_compat.DEFAULT_MODEL,
                max_tokens=200,
                system="",
                messages=[{"role": "user", "content": "lookup"}],
                tools=[{"name": "dns_lookup", "description": "", "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}}],
                timeout_s=5,
                max_retries=0,
            )
            self.assertEqual(resp.stop_reason, "tool_use")
            self.assertEqual(resp.content[0].name, "dns_lookup")
            self.assertEqual(resp.content[0].input["domain"], "example.com")
        finally:
            ollama_compat._http_post_json = orig  # type: ignore[assignment]

    def test_tool_mode_final_returns_end_turn(self):
        def fake_post(url, payload, timeout_s):
            return {"message": {"content": '{"tool":"final","input":{"text":"done"}}'}}

        orig = ollama_compat._http_post_json
        try:
            ollama_compat._http_post_json = fake_post  # type: ignore[assignment]
            resp = ollama_compat.OllamaClient().messages.create(
                model=ollama_compat.DEFAULT_MODEL,
                max_tokens=200,
                system="",
                messages=[{"role": "user", "content": "finish"}],
                tools=[{"name": "dns_lookup", "description": "", "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}}],
                timeout_s=5,
                max_retries=0,
            )
            self.assertEqual(resp.stop_reason, "end_turn")
            self.assertEqual(resp.content[0].text, "done")
        finally:
            ollama_compat._http_post_json = orig  # type: ignore[assignment]

