import unittest
from unittest.mock import patch

import ollama_compat


class TestOllamaRepairFlow(unittest.TestCase):
    def test_repair_attempt_happens(self):
        bad = {"message": {"content": "not json at all"}}
        good = {"message": {"content": '{"summary":"x","infrastructure":{"hosting":null,"cdn":null,"org":null},"subdomains":[],"technology_stack":[],"open_ports":[],"risk_score":0,"misconfig_count":0,"attack_surface_notes":""}'}}

        with patch.object(ollama_compat, "_http_post_json", side_effect=[bad, good]):
            res = ollama_compat.ollama_chat(
                [{"role": "user", "content": "hi"}],
                model="dummy",
                timeout_s=1,
                max_retries=0,
                response_format="json",
                schema_hint="return an object",
            )
            self.assertTrue(res["ok"])
            self.assertTrue(res["repaired"])
            self.assertIsInstance(res["data"], dict)


if __name__ == "__main__":
    unittest.main()
