"""Redirect-safe HTTP helpers for target-facing ARES requests."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from utils.scope_validator import ScopeValidator, normalize_target_url


REDIRECT_CODES = {301, 302, 303, 307, 308}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class SafeHTTPResult:
    status: int
    headers: dict
    body: bytes
    url: str
    redirects: list[dict] = field(default_factory=list)
    blocked_redirect: dict | None = None
    error: str = ""


def _close(response) -> None:
    close = getattr(response, "close", None)
    if callable(close):
        close()


def safe_http_request(
    url: str,
    scope: ScopeValidator,
    *,
    method: str = "GET",
    timeout: int | float = 10,
    headers: dict | None = None,
    max_body_bytes: int = 4096,
    max_redirects: int = 5,
    ssl_context: ssl.SSLContext | None = None,
    allow_https_downgrade: bool = False,
) -> SafeHTTPResult:
    """Fetch a URL while validating the initial target and every redirect hop."""

    current = normalize_target_url(url)
    scope.validate_network_target(current)
    redirects = []
    visited = set()
    ctx = ssl_context or ssl.create_default_context()
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))

    while True:
        if current in visited:
            return SafeHTTPResult(0, {}, b"", current, redirects, error="redirect_loop")
        visited.add(current)
        request = urllib.request.Request(current, headers=headers or {}, method=method)
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        except Exception as exc:
            return SafeHTTPResult(
                0,
                {},
                b"",
                current,
                redirects,
                error=f"{type(exc).__name__}: {exc}",
            )

        status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
        response_headers = dict(getattr(response, "headers", {}) or {})
        if status in REDIRECT_CODES:
            location = response_headers.get("Location") or response_headers.get("location")
            if not location:
                _close(response)
                return SafeHTTPResult(status, response_headers, b"", current, redirects)
            destination = urllib.parse.urljoin(current, location)
            try:
                destination = normalize_target_url(destination)
                if (
                    not allow_https_downgrade
                    and urllib.parse.urlsplit(current).scheme == "https"
                    and urllib.parse.urlsplit(destination).scheme == "http"
                ):
                    raise ValueError("HTTPS-to-HTTP redirect is blocked")
                scope.validate_network_target(destination)
            except ValueError as exc:
                evidence = {
                    "source_url": current,
                    "location": location,
                    "destination_url": destination,
                    "status_code": status,
                    "reason": str(exc),
                    "body_fetched": False,
                }
                _close(response)
                return SafeHTTPResult(
                    status,
                    response_headers,
                    b"",
                    current,
                    redirects,
                    blocked_redirect=evidence,
                    error="redirect_blocked",
                )
            redirects.append({
                "source_url": current,
                "destination_url": destination,
                "status_code": status,
            })
            if len(redirects) > max_redirects:
                _close(response)
                return SafeHTTPResult(status, response_headers, b"", current, redirects, error="max_redirects")
            _close(response)
            current = destination
            if status == 303 and method not in {"GET", "HEAD"}:
                method = "GET"
            continue

        body = b""
        if method != "HEAD":
            try:
                body = response.read(max(max_body_bytes, 0))
            except Exception:
                body = b""
        _close(response)
        return SafeHTTPResult(status, response_headers, body, current, redirects)
