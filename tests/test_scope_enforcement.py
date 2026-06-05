"""Scope enforcement audit tests."""

import importlib
import os
from unittest import mock

os.environ["ARES_SAFE_TARGETS"] = ""

from utils.scope_validator import Scope, ScopeValidator


def _validator(domains=None, ip_ranges=None):
    scope = Scope(
        domains=domains or ["example.com", "*.example.com"],
        ip_ranges=ip_ranges or [],
    )
    return ScopeValidator(scope)


def test_in_scope_domain():
    v = _validator()
    ok, reason = v.validate("example.com")
    assert ok


def test_wildcard_subdomain():
    v = _validator()
    ok, _ = v.validate("sub.example.com")
    assert ok


def test_out_of_scope():
    v = _validator()
    ok, reason = v.validate("evil.com")
    assert not ok
    assert reason


def test_safe_target_bypass():
    os.environ["ARES_SAFE_TARGETS"] = "allowed-demo.com"
    import utils.config as config
    import utils.scope_validator as sv

    importlib.reload(config)
    importlib.reload(sv)
    v = sv.ScopeValidator(sv.Scope(domains=["other.com"]))
    ok, _ = v.validate("allowed-demo.com")
    assert ok
    os.environ["ARES_SAFE_TARGETS"] = ""
    importlib.reload(config)
    importlib.reload(sv)


def test_ip_not_in_range():
    v = _validator(ip_ranges=["10.0.0.0/24"])
    ok, _ = v.validate("192.168.1.1")
    assert isinstance(ok, bool)
    assert not ok


def test_js_intelligence_skips_out_of_scope_script_fetches():
    import tools.js_intelligence as js

    v = _validator(domains=["example.com"])
    html = '<script src="https://evil.com/app.js"></script>'
    with mock.patch.object(js, "_fetch", return_value="") as fetch:
        out = js.js_intelligence("https://example.com", v, seed_html=html)
    fetch.assert_not_called()
    assert out["script_count"] == 0
