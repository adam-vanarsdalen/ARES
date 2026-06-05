import urllib.error

import tools.passive_url_discovery as passive
from tools.passive_url_discovery import passive_url_discovery
from utils.scope_validator import Scope, ScopeValidator


class _Response:
    def __init__(self, status, body):
        self.status = status
        self._body = body.encode("utf-8")

    def read(self, *_args):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _Opener:
    def __init__(self, mapping, requested):
        self.mapping = mapping
        self.requested = requested

    def open(self, req, timeout=None):
        url = req.full_url
        self.requested.append(url)
        status, body = self.mapping.get(url, (404, ""))
        if status >= 400:
            raise urllib.error.HTTPError(url, status, "not found", {}, None)
        return _Response(status, body)


def _mock_fetch(monkeypatch, mapping):
    requested = []

    def build_opener(*_args, **_kwargs):
        return _Opener(mapping, requested)

    monkeypatch.setattr(passive.urllib.request, "build_opener", build_opener)
    return requested


def _scope():
    return ScopeValidator(Scope(domains=["example.com"]))


def test_robots_allow_disallow_paths_normalize_to_in_scope_urls(monkeypatch):
    requested = _mock_fetch(monkeypatch, {
        "http://example.com/robots.txt": (
            200,
            """
            User-agent: *
            Allow: /public
            Disallow: /admin
            Disallow: https://evil.test/private
            """,
        ),
    })

    out = passive_url_discovery("http://example.com", _scope())

    assert out["robots"]["allow"] == ["http://example.com/public"]
    assert out["robots"]["disallow"] == ["http://example.com/admin"]
    assert "https://evil.test/private" not in out["robots"]["urls"]
    assert "http://example.com/robots.txt" in requested


def test_sitemap_urlset_drops_out_of_scope_urls(monkeypatch):
    _mock_fetch(monkeypatch, {
        "http://example.com/sitemap.xml": (
            200,
            """<?xml version="1.0"?>
            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
              <url><loc>http://example.com/products</loc></url>
              <url><loc>https://evil.test/login</loc></url>
            </urlset>""",
        ),
    })

    out = passive_url_discovery("http://example.com", _scope())

    assert out["sitemaps"]["urls"] == ["http://example.com/products"]
    assert out["discovered_urls"] == ["http://example.com/products"]


def test_sitemapindex_fetches_child_sitemaps_up_to_cap(monkeypatch):
    monkeypatch.setattr(passive, "SITEMAP_MAX_CHILDREN", 2)
    requested = _mock_fetch(monkeypatch, {
        "http://example.com/sitemap.xml": (
            200,
            """<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
              <sitemap><loc>http://example.com/sitemap-a.xml</loc></sitemap>
              <sitemap><loc>http://example.com/sitemap-b.xml</loc></sitemap>
              <sitemap><loc>http://example.com/sitemap-c.xml</loc></sitemap>
            </sitemapindex>""",
        ),
        "http://example.com/sitemap-a.xml": (
            200,
            "<urlset><url><loc>http://example.com/a</loc></url></urlset>",
        ),
        "http://example.com/sitemap-b.xml": (
            200,
            "<urlset><url><loc>http://example.com/b</loc></url></urlset>",
        ),
    })

    out = passive_url_discovery("http://example.com", _scope())

    assert out["sitemaps"]["child_sitemaps"] == [
        "http://example.com/sitemap-a.xml",
        "http://example.com/sitemap-b.xml",
    ]
    assert out["sitemaps"]["urls"] == ["http://example.com/a", "http://example.com/b"]
    assert "http://example.com/sitemap-c.xml" not in requested


def test_security_txt_fields_are_extracted(monkeypatch):
    _mock_fetch(monkeypatch, {
        "http://example.com/.well-known/security.txt": (
            200,
            """
            Contact: mailto:security@example.com
            Policy: https://example.com/security
            Hiring: https://example.com/jobs
            Encryption: https://example.com/pgp.txt
            Acknowledgments: https://example.com/thanks
            """,
        ),
    })

    out = passive_url_discovery("http://example.com", _scope())

    assert out["security_txt"]["status_code"] == 200
    assert out["security_txt"]["fields"]["contact"] == ["mailto:security@example.com"]
    assert out["security_txt"]["fields"]["policy"] == ["https://example.com/security"]


def test_suggested_dorks_are_generated_but_never_executed(monkeypatch):
    requested = _mock_fetch(monkeypatch, {})

    out = passive_url_discovery("http://example.com", _scope())

    assert out["suggested_dorks"]
    assert out["coverage"]["suggested_dorks"]["status"] == "generated_not_executed"
    assert requested == [
        "http://example.com/robots.txt",
        "http://example.com/sitemap.xml",
        "http://example.com/.well-known/security.txt",
    ]
    assert not any("site:" in url for url in requested)
