"""Tests for passive TLS and HTTP/2 fingerprinting."""

from unittest.mock import MagicMock, patch

from tools.fingerprinting import http2_fingerprint, ja3_fingerprint


def _tls_socket():
    sock = MagicMock()
    sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    sock.version.return_value = "TLSv1.3"
    sock.shared_ciphers.return_value = [
        ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
    ]
    return sock


def test_successful_ja3_returns_md5_hex():
    tls_sock = _tls_socket()
    context = MagicMock()
    context.wrap_socket.return_value = tls_sock
    with (
        patch("tools.fingerprinting.ssl.create_default_context", return_value=context),
        patch("tools.fingerprinting.socket.create_connection", return_value=MagicMock()),
    ):
        result = ja3_fingerprint("example.com")
    assert result["status"] == "success"
    assert len(result["ja3_hash"]) == 32
    int(result["ja3_hash"], 16)


def test_ja3_connection_failure_is_non_fatal():
    with patch("tools.fingerprinting.socket.create_connection", side_effect=OSError("offline")):
        result = ja3_fingerprint("example.com")
    assert result["status"] == "failed"
    assert result["ja3_hash"] == ""


def test_http2_alpn_detection():
    tls_sock = _tls_socket()
    tls_sock.selected_alpn_protocol.return_value = "h2"
    tls_sock.recv.return_value = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    context = MagicMock()
    context.wrap_socket.return_value = tls_sock
    with (
        patch("tools.fingerprinting.ssl.create_default_context", return_value=context),
        patch("tools.fingerprinting.socket.create_connection", return_value=MagicMock()),
    ):
        result = http2_fingerprint("example.com")
    assert result["http2_supported"] is True
    assert result["settings_frame_detected"] is True
