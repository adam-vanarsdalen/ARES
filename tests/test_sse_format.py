import json
import unittest

import server


class TestSSEFormatting(unittest.TestCase):
    def test_format_sse_event_is_json(self):
        evt = server.format_sse_event("log", {"tag": "TEST", "msg": "hello"})
        self.assertEqual(evt["event"], "log")
        parsed = json.loads(evt["data"])
        self.assertEqual(parsed["tag"], "TEST")
        self.assertEqual(parsed["msg"], "hello")


if __name__ == "__main__":
    unittest.main()
