import unittest

import tools.network_tools as network_tools


class TestNoRedirectOpener(unittest.TestCase):
    def test_urlopen_no_redirect_does_not_pass_context_kwarg(self):
        calls = {}

        class FakeOpener:
            def open(self, req, data=None, timeout=None):
                calls["timeout"] = timeout
                return None

        def fake_build_opener(*handlers):
            calls["handlers"] = handlers
            return FakeOpener()

        orig = network_tools.urllib.request.build_opener
        try:
            network_tools.urllib.request.build_opener = fake_build_opener  # type: ignore[assignment]
            network_tools._urlopen_no_redirect(req=object(), timeout=7, ctx=None)  # type: ignore[arg-type]
            self.assertEqual(calls.get("timeout"), 7)
        finally:
            network_tools.urllib.request.build_opener = orig  # type: ignore[assignment]

