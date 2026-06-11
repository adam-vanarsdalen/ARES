from unittest import mock

import pytest

from tools import tls_audit as tls
from tools.tls_audit import tls_audit
from utils.scope_validator import Scope, ScopeValidator


class _FakeTLSSock:
    def __init__(self, cert=None, version="TLSv1.3", cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)):
        self._cert = cert or {}
        self._version = version
        self._cipher = cipher

    def getpeercert(self):
        return self._cert

    def version(self):
        return self._version

    def cipher(self):
        return self._cipher

    def close(self):
        return None


def _scope():
    return ScopeValidator(Scope(domains=["example.com"]))


def _cert(
    not_after="Jan  1 00:00:00 2035 GMT",
    not_before="Jan  1 00:00:00 2024 GMT",
    subject_cn="example.com",
    issuer_cn="Example CA",
    sans=None,
):
    return {
        "subject": ((("commonName", subject_cn),),),
        "issuer": ((("commonName", issuer_cn),),),
        "notBefore": not_before,
        "notAfter": not_after,
        "subjectAltName": tuple(("DNS", item) for item in (sans or [subject_cn])),
    }


def test_expired_certificate_generates_finding():
    with (
        mock.patch.object(tls, "_handshake", return_value=_FakeTLSSock(cert=_cert(not_after="Jan  1 00:00:00 2020 GMT"))),
        mock.patch.object(tls, "_validated_handshake", return_value={"trusted": True, "hostname_validated": True}),
        mock.patch.object(tls, "_protocol_support", return_value={p: "refused" for p in tls.PROTOCOLS}),
    ):
        out = tls_audit("https://example.com", _scope())

    assert out["certificate"]["expired"] is True
    assert any(finding["title"] == "Expired TLS certificate" for finding in out["findings"])


def test_tls10_accepted_generates_finding():
    with (
        mock.patch.object(tls, "_handshake", return_value=_FakeTLSSock(cert=_cert())),
        mock.patch.object(tls, "_validated_handshake", return_value={"trusted": True, "hostname_validated": True}),
        mock.patch.object(tls, "_protocol_support", return_value={"TLSv1.0": "accepted", "TLSv1.1": "refused", "TLSv1.2": "accepted", "TLSv1.3": "accepted"}),
    ):
        out = tls_audit("https://example.com", _scope())

    assert out["protocols"]["TLSv1.0"] == "accepted"
    assert any(finding["title"] == "TLS 1.0 accepted" for finding in out["findings"])


def test_hostname_mismatch_generates_finding():
    with (
        mock.patch.object(tls, "_handshake", return_value=_FakeTLSSock(cert=_cert(subject_cn="other.test", sans=["other.test"]))),
        mock.patch.object(tls, "_validated_handshake", return_value={"trusted": True, "hostname_validated": True}),
        mock.patch.object(tls, "_protocol_support", return_value={p: "refused" for p in tls.PROTOCOLS}),
    ):
        out = tls_audit("https://example.com", _scope())

    assert out["certificate"]["hostname_match"] is False
    assert any(finding["title"] == "TLS hostname mismatch" for finding in out["findings"])


def test_out_of_scope_tls_audit_is_blocked_before_socket_use():
    with mock.patch.object(tls, "_handshake") as handshake:
        with pytest.raises(ValueError):
            tls_audit("https://evil.test", _scope())

    handshake.assert_not_called()


def test_all_protocol_errors_mark_tls_coverage_failed():
    with (
        mock.patch.object(tls, "_handshake", side_effect=TimeoutError("timeout")),
        mock.patch.object(tls, "_validated_handshake", side_effect=TimeoutError("timeout")),
        mock.patch.object(tls, "_protocol_support", return_value={p: "error" for p in tls.PROTOCOLS}),
    ):
        out = tls_audit("https://example.com", _scope())

    assert out["coverage"]["certificate"] == "failed"
    assert out["coverage"]["protocols"] == "failed"
    assert out["coverage"]["protocol_error"] == "all_protocol_checks_failed"


def test_not_yet_valid_missing_san_and_untrusted_are_reported():
    cert = _cert(not_before="Jan  1 00:00:00 2035 GMT", sans=[])
    cert["subjectAltName"] = ()
    with (
        mock.patch.object(tls, "_handshake", return_value=_FakeTLSSock(cert=cert)),
        mock.patch.object(
            tls,
            "_validated_handshake",
            return_value={"trusted": False, "hostname_validated": True, "error": "self signed"},
        ),
        mock.patch.object(tls, "_protocol_support", return_value={p: "refused" for p in tls.PROTOCOLS}),
    ):
        out = tls_audit("https://example.com", _scope())

    titles = {finding["title"] for finding in out["findings"]}
    assert "TLS certificate is not yet valid" in titles
    assert "TLS certificate missing SAN" in titles
    assert "Untrusted TLS certificate chain" in titles
