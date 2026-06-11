"""Best-effort passive TLS and HTTP/2 service fingerprinting."""

from __future__ import annotations

import hashlib
import socket
import ssl

from utils.config import TLS_TIMEOUT


def _empty_ja3(host: str, port: int, error: str = "") -> dict:
    """Return the normalized failed JA3 approximation result."""
    return {
        "host": host or "",
        "port": port,
        "ja3_hash": "",
        "tls_version": "",
        "negotiated_cipher": "",
        "fingerprint_method": "post_handshake_approximation",
        "source": "ja3_fingerprint",
        "status": "failed",
        "error": error,
    }


def _empty_http2(host: str, port: int, error: str = "") -> dict:
    """Return the normalized failed HTTP/2 fingerprint result."""
    return {
        "host": host or "",
        "port": port,
        "http2_supported": False,
        "alpn_negotiated": "",
        "settings_frame_detected": False,
        "source": "http2_fingerprint",
        "status": "failed",
        "error": error,
    }


def ja3_fingerprint(host: str, port: int = 443) -> dict:
    """
    Build a best-effort JA3 approximation from post-handshake TLS data.

    Python's ssl module does not expose raw ClientHello bytes, so this is not
    a canonical JA3 calculation. It hashes the negotiated TLS version, cipher,
    and any shared cipher names reported after the handshake.
    """
    raw_sock = None
    tls_sock = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw_sock = socket.create_connection((host, port), timeout=TLS_TIMEOUT)
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        cipher = tls_sock.cipher() or ()
        cipher_name = str(cipher[0]) if cipher else ""
        tls_version = str(tls_sock.version() or "")
        shared = tls_sock.shared_ciphers() or []
        shared_names = [
            str(item[0])
            for item in shared
            if isinstance(item, (list, tuple)) and item
        ]
        fingerprint = ",".join([tls_version, cipher_name, *shared_names])
        digest = hashlib.md5(
            fingerprint.encode("utf-8", errors="ignore"),
            usedforsecurity=False,
        ).hexdigest()
        return {
            "host": host,
            "port": port,
            "ja3_hash": digest,
            "tls_version": tls_version,
            "negotiated_cipher": cipher_name,
            "fingerprint_method": "post_handshake_approximation",
            "source": "ja3_fingerprint",
            "status": "success",
            "error": "",
        }
    except Exception as exc:
        return _empty_ja3(host, port, type(exc).__name__)
    finally:
        for sock in (tls_sock, raw_sock):
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass


def http2_fingerprint(host: str, port: int = 443) -> dict:
    """Detect HTTP/2 ALPN negotiation and a leading SETTINGS frame."""
    raw_sock = None
    tls_sock = None
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        raw_sock = socket.create_connection((host, port), timeout=TLS_TIMEOUT)
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        selected = str(tls_sock.selected_alpn_protocol() or "")
        settings_detected = False
        if selected == "h2":
            tls_sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            frame = tls_sock.recv(9)
            settings_detected = len(frame) >= 4 and frame[3] == 0x04
        return {
            "host": host,
            "port": port,
            "http2_supported": selected == "h2",
            "alpn_negotiated": selected,
            "settings_frame_detected": settings_detected,
            "source": "http2_fingerprint",
            "status": "success",
            "error": "",
        }
    except Exception as exc:
        return _empty_http2(host, port, type(exc).__name__)
    finally:
        for sock in (tls_sock, raw_sock):
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
