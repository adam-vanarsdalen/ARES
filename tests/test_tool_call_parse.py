import unittest

import ollama_compat


class TestToolCallParse(unittest.TestCase):
    def test_parses_tool_call_with_preamble(self):
        txt = 'Sure! {"tool":"dns_lookup","input":{"domain":"example.com"}} Thanks.'
        self.assertEqual(
            ollama_compat._parse_tool_call(txt),
            {"tool": "dns_lookup", "input": {"domain": "example.com"}},
        )

    def test_parses_tool_call_in_fence(self):
        txt = "```json\n{\"tool\": \"whois_lookup\", \"input\": {\"domain\": \"example.com\"}}\n```"
        self.assertEqual(
            ollama_compat._parse_tool_call(txt),
            {"tool": "whois_lookup", "input": {"domain": "example.com"}},
        )

    def test_rejects_non_tool_json(self):
        self.assertIsNone(ollama_compat._parse_tool_call('{"a": 1}'))

    def test_rejects_missing_input(self):
        self.assertIsNone(ollama_compat._parse_tool_call('{"tool": "dns_lookup"}'))

