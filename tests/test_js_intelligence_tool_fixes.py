import unittest
from unittest import mock
import urllib.error


import tools.js_intelligence as js
from utils.scope_validator import Scope, ScopeValidator


class _FakeResponse:
    def __init__(self, url: str, body: bytes, headers: dict[str, str] | None = None, status: int = 200):
        self.url = url
        self._body = body
        self.headers = headers or {}
        self.status = status
        self._pos = 0

    def read(self, n: int | None = None):
        if n is None:
            n = len(self._body) - self._pos
        chunk = self._body[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeOpener:
    def __init__(self, routes: dict[str, object]):
        self.routes = routes

    def open(self, req, timeout=None):
        url = getattr(req, "full_url", None) or req.get_full_url()
        action = self.routes[url]
        if isinstance(action, Exception):
            raise action
        return action


class TestJSIntelligenceToolFixes(unittest.TestCase):
    def test_d0_vulnweb_targets_get_extended_fetch_timeouts(self):
        self.assertTrue(js._is_slow_target("https://testphp.vulnweb.com"))  # type: ignore[attr-defined]
        self.assertFalse(js._is_slow_target("https://example.com"))  # type: ignore[attr-defined]

    def test_d1_bounded_redirects_and_size_guard(self):
        # a -> b redirect, b returns JS
        redirect_headers = {"Location": "http://b.example/js/app.js"}
        err = urllib.error.HTTPError("http://a.example/js/app.js", 302, "Found", redirect_headers, None)
        body = b"x" * (js._MAX_FETCH_BYTES + 1000)
        resp = _FakeResponse(
            "http://b.example/js/app.js",
            body=body,
            headers={"Content-Type": "application/javascript", "Content-Length": str(len(body))},
        )
        opener = _FakeOpener({
            "http://a.example/js/app.js": err,
            "http://b.example/js/app.js": resp,
        })

        scope = ScopeValidator(Scope(domains=["*.example"]), enforce_resolution=True)
        with (
            mock.patch("urllib.request.build_opener", return_value=opener),
            mock.patch("utils.scope_validator.resolve_target_ips", return_value=["93.184.216.34"]),
        ):
            with self.assertLogs("tools.js_intelligence", level="WARNING"):
                out = js._fetch("http://a.example/js/app.js", timeout=1, scope=scope)

        self.assertEqual(len(out), js._MAX_FETCH_BYTES)

    def test_d1_max_redirects_exceeded_returns_empty(self):
        # a -> b -> c, but allow only 1 redirect
        err_a = urllib.error.HTTPError("http://a/", 302, "Found", {"Location": "http://b/"}, None)
        err_b = urllib.error.HTTPError("http://b/", 302, "Found", {"Location": "http://c/"}, None)
        opener = _FakeOpener({"http://a/": err_a, "http://b/": err_b})
        scope = ScopeValidator(Scope(domains=["a", "b", "c"]), enforce_resolution=True)
        with (
            mock.patch("urllib.request.build_opener", return_value=opener),
            mock.patch("utils.scope_validator.resolve_target_ips", return_value=["93.184.216.34"]),
            mock.patch("tools.js_intelligence._MAX_REDIRECTS", 1),
        ):
            with self.assertLogs("tools.js_intelligence", level="WARNING"):
                out = js._fetch("http://a/", timeout=1, scope=scope)
        self.assertEqual(out, "")

    def test_d1_redirect_to_private_address_is_blocked_before_fetch(self):
        error = urllib.error.HTTPError(
            "https://example.com/app.js",
            302,
            "Found",
            {"Location": "http://127.0.0.1/private.js"},
            None,
        )
        opener = _FakeOpener({"https://example.com/app.js": error})
        scope = ScopeValidator(Scope(domains=["example.com"]), enforce_resolution=True)

        def resolve(value):
            return ["127.0.0.1"] if "127.0.0.1" in value else ["93.184.216.34"]

        blocked = []
        with (
            mock.patch("urllib.request.build_opener", return_value=opener),
            mock.patch("utils.scope_validator.resolve_target_ips", side_effect=resolve),
            self.assertLogs("tools.js_intelligence", level="WARNING"),
        ):
            out = js._fetch(
                "https://example.com/app.js",
                timeout=1,
                scope=scope,
                blocked_redirects=blocked,
            )
        self.assertEqual(out, "")
        self.assertEqual(len(blocked), 1)
        self.assertFalse(blocked[0]["body_fetched"])

    def test_d2_secret_dedupe_keeps_same_preview_from_different_scripts(self):
        scope = Scope(domains=["example.com", "*.example.com"])
        validator = ScopeValidator(scope)

        html = '<script src="https://cdn.example.com/a.js"></script><script src="https://cdn.example.com/b.js"></script>'
        js_a = 'const apiKey="ABCDEFGHIJKLMNOPQRSTUVWX1234567890";'
        js_b = 'const apiKey="ABCDEFGHIJKLMNOPQRSTUVWX1234567890";'

        def fake_fetch(url, timeout=10, **kwargs):
            if url == "https://example.com":
                return html
            if url.endswith("/a.js"):
                return js_a
            if url.endswith("/b.js"):
                return js_b
            return ""

        with mock.patch("tools.js_intelligence._fetch", side_effect=fake_fetch):
            res = js.js_intelligence("https://example.com", validator, max_scripts=8)

        self.assertEqual(res["script_count"], 2)
        # Should keep both because they come from different scripts (even if previews match).
        self.assertEqual(len(res["secrets"]), 2)

    def test_d3_offscope_cdn_js_is_not_analyzed(self):
        scope = Scope(domains=["example.com", "*.example.com"])
        validator = ScopeValidator(scope)

        html = '<script src="https://cdn.other.net/app.js"></script>'
        js_body = 'fetch("/api/v1/users");'

        def fake_fetch(url, timeout=10, **kwargs):
            if url == "https://example.com":
                return html
            if url == "https://cdn.other.net/app.js":
                return js_body
            return ""

        with mock.patch("tools.js_intelligence._fetch", side_effect=fake_fetch):
            res = js.js_intelligence("https://example.com", validator, max_scripts=8)

        self.assertNotIn("/api/v1/users", res["endpoints"])
        self.assertNotIn("https://cdn.other.net/app.js", res["scripts_analyzed"])
        self.assertEqual(res["script_count"], 0)

    def test_d4_fallback_page_candidates_and_seed_html_are_used(self):
        scope = Scope(domains=["testphp.vulnweb.com", "*.vulnweb.com"])
        validator = ScopeValidator(scope)

        html = '<link rel="modulepreload" href="/assets/app.js">'
        js_body = 'fetch("/api/v1/users");'

        def fake_fetch(url, timeout=10, **kwargs):
            if url == "https://testphp.vulnweb.com/index.php":
                return html
            if url == "https://testphp.vulnweb.com/assets/app.js":
                return js_body
            return ""

        with mock.patch("tools.js_intelligence._fetch", side_effect=fake_fetch):
            res = js.js_intelligence(
                "https://testphp.vulnweb.com",
                validator,
                max_scripts=8,
                fallback_urls=["https://testphp.vulnweb.com/index.php"],
            )

        self.assertEqual(res["page_url"], "https://testphp.vulnweb.com/index.php")
        self.assertIn("/api/v1/users", res["endpoints"])
        self.assertIn("https://testphp.vulnweb.com/assets/app.js", res["scripts_analyzed"])
        self.assertEqual(res["timeout_profile"]["page_fetch_timeout"], 20)
        self.assertEqual(res["timeout_profile"]["script_fetch_timeout"], 25)

    def test_d5_html_routes_are_collected_without_external_scripts(self):
        scope = Scope(domains=["demo.testfire.net", "*.testfire.net"])
        validator = ScopeValidator(scope)

        html = """
        <html>
          <body>
            <form method="get" action="/search.jsp"></form>
            <a href="/login.jsp">Login</a>
            <a href="/feedback.jsp">Feedback</a>
            <a href="/index.jsp?content=inside_contact.htm">Contact</a>
          </body>
        </html>
        """

        def fake_fetch(url, timeout=10, **kwargs):
            if url == "https://demo.testfire.net":
                return html
            return ""

        with mock.patch("tools.js_intelligence._fetch", side_effect=fake_fetch):
            res = js.js_intelligence("https://demo.testfire.net", validator, max_scripts=8)

        self.assertEqual(res["script_count"], 0)
        self.assertIn("/search.jsp", res["endpoints"])
        self.assertIn("/login.jsp", res["endpoints"])
        self.assertIn("/feedback.jsp", res["endpoints"])
        self.assertIn("/index.jsp?content=inside_contact.htm", res["endpoints"])
        self.assertGreaterEqual(len(res["html_routes"]), 4)

    def test_d6_bounded_crawl_collects_forms_and_second_page_scripts(self):
        scope = Scope(domains=["example.com", "*.example.com"])
        validator = ScopeValidator(scope)

        index_html = """
        <a href="/products.asp">Products</a>
        <form method="post" action="/search.asp">
          <input name="q">
        </form>
        """
        products_html = '<script src="/static/app.js"></script>'
        js_body = 'fetch("/api/v1/catalog");'

        def fake_fetch(url, timeout=10, **kwargs):
            if url == "https://example.com":
                return index_html
            if url == "https://example.com/products.asp":
                return products_html
            if url == "https://example.com/static/app.js":
                return js_body
            return ""

        with mock.patch("tools.js_intelligence._fetch", side_effect=fake_fetch):
            res = js.js_intelligence("https://example.com", validator, max_scripts=8)

        self.assertIn("/products.asp", res["endpoints"])
        self.assertIn("/search.asp", res["endpoints"])
        self.assertIn("/api/v1/catalog", res["endpoints"])
        self.assertEqual(res["form_count"], 1)
        self.assertEqual(res["forms"][0]["fields"], ["q"])
        self.assertIn("https://example.com/static/app.js", res["scripts_analyzed"])
        self.assertGreaterEqual(len(res["pages_crawled"]), 2)


if __name__ == "__main__":
    unittest.main()
