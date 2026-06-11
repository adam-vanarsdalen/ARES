"""Tests for passive C2 IOC detection."""

import json
from unittest.mock import patch

from tools import c2_detection


class _Response:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


def _reset_caches():
    c2_detection._FEODO_CACHE = set()
    c2_detection._FEODO_TS = 0.0
    c2_detection._FEODO_ERROR = ""
    c2_detection._URLHAUS_CACHE = set()
    c2_detection._URLHAUS_TS = 0.0
    c2_detection._URLHAUS_ERROR = ""


def _feeds(feodo_ips, urlhaus_text=""):
    return [
        _Response(json.dumps([{"ip_address": ip} for ip in feodo_ips]).encode()),
        _Response(urlhaus_text.encode()),
    ]


def test_known_feodo_ip_is_flagged():
    _reset_caches()
    with patch("urllib.request.urlopen", side_effect=_feeds(["198.51.100.10"])):
        result = c2_detection.check_c2_ioc("198.51.100.10")
    assert result["is_c2_ioc"] is True
    assert result["matched_feeds"] == ["feodo_tracker"]


def test_clean_ip_is_not_flagged():
    _reset_caches()
    with patch("urllib.request.urlopen", side_effect=_feeds([])):
        result = c2_detection.check_c2_ioc("203.0.113.10")
    assert result["status"] == "success"
    assert result["is_c2_ioc"] is False


def test_urlhaus_hostname_is_flagged():
    _reset_caches()
    with patch(
        "urllib.request.urlopen",
        side_effect=_feeds([], "# comment\nhttps://malware.example/payload\n"),
    ):
        result = c2_detection.check_c2_ioc("https://malware.example:443/path")
    assert result["indicator"] == "malware.example"
    assert result["matched_feeds"] == ["urlhaus"]


def test_network_failure_returns_failed():
    _reset_caches()
    with patch("urllib.request.urlopen", side_effect=OSError("offline")):
        result = c2_detection.check_c2_ioc("198.51.100.10")
    assert result["status"] == "failed"
    assert result["is_c2_ioc"] is False
