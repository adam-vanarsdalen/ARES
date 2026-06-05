import json
import socket
import urllib.error
from unittest import mock

from tools.external_enrichment import internetdb_lookup, reverse_ip_lookup
from utils.scope_validator import Scope, ScopeValidator


class _Response:
    def __init__(self, payload: bytes):
        self.payload = payload

    def read(self):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_internetdb_lookup_success_normalizes_response():
    payload = {
        "ip": "203.0.113.10",
        "ports": [443, "80", "bad"],
        "hostnames": ["www.example.com", "www.example.com"],
        "vulns": ["CVE-2024-0001"],
        "cpes": ["cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*"],
        "tags": ["self-signed"],
    }

    with mock.patch("urllib.request.urlopen", return_value=_Response(json.dumps(payload).encode())):
        out = internetdb_lookup("203.0.113.10")

    assert out == {
        "ip": "203.0.113.10",
        "ports": [80, 443],
        "hostnames": ["www.example.com"],
        "vulns": ["CVE-2024-0001"],
        "cpes": ["cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*"],
        "tags": ["self-signed"],
        "source": "shodan_internetdb",
        "status": "success",
        "error": "",
    }


def test_internetdb_lookup_404_is_no_data():
    err = urllib.error.HTTPError("https://internetdb.shodan.io/203.0.113.10", 404, "Not Found", {}, None)
    with mock.patch("urllib.request.urlopen", side_effect=err):
        out = internetdb_lookup("203.0.113.10")

    assert out["status"] == "no_data"
    assert out["error"] == ""
    assert out["ports"] == []


def test_internetdb_lookup_timeout_is_failed():
    with mock.patch("urllib.request.urlopen", side_effect=socket.timeout("timed out")):
        out = internetdb_lookup("203.0.113.10")

    assert out["status"] == "failed"
    assert out["error"] == "timeout"


def test_internetdb_lookup_malformed_json_is_failed():
    with mock.patch("urllib.request.urlopen", return_value=_Response(b"{not-json")):
        out = internetdb_lookup("203.0.113.10")

    assert out["status"] == "failed"
    assert out["error"] == "malformed_json"


def test_reverse_ip_lookup_success_parses_plaintext_hosts():
    payload = b"www.example.com\napi.example.com\nwww.example.com\n"
    validator = ScopeValidator(Scope(domains=["example.com"]))
    with mock.patch("urllib.request.urlopen", return_value=_Response(payload)):
        out = reverse_ip_lookup("203.0.113.10", validator)

    assert out == {
        "query": "203.0.113.10",
        "hostnames": ["api.example.com", "www.example.com"],
        "ownership_unverified": True,
        "source": "hackertarget_reverse_ip",
        "status": "success",
        "error": "",
    }


def test_reverse_ip_lookup_api_count_exceeded_is_nonfatal_no_data():
    validator = ScopeValidator(Scope(domains=["example.com"]))
    with mock.patch("urllib.request.urlopen", return_value=_Response(b"API count exceeded")):
        out = reverse_ip_lookup("https://example.com", validator)

    assert out["query"] == "example.com"
    assert out["hostnames"] == []
    assert out["status"] == "no_data"
    assert out["error"] == "api_count_exceeded"


def test_reverse_ip_lookup_domain_must_be_in_scope():
    validator = ScopeValidator(Scope(domains=["example.com"]))
    out = reverse_ip_lookup("https://other.test", validator)

    assert out["status"] == "failed"
    assert out["hostnames"] == []
