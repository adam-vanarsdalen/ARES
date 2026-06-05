"""Non-destructive red-team verification helpers."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.parse
import urllib.request
from enum import StrEnum

from utils.config import API_ENUM_MAX_PATHS
from utils.scope_validator import ScopeValidator


MARKER_URL = "https://example.invalid/ares-open-redirect"
MARKER_HOST = "example.invalid"
API_ENUM_PATHS = (
    "/api", "/api/v1", "/api/v2", "/api/v1/users", "/api/v2/users",
    "/graphql", "/api-docs", "/swagger.json", "/swagger/v1/swagger.json",
    "/openapi.json", "/api/swagger",
)
AUTH_PANEL_PATHS = ("/admin", "/admin/login", "/login", "/wp-admin")


class VerificationStatus(StrEnum):
    CONFIRMED = "confirmed"
    STRONGLY_INDICATED = "strongly_indicated"
    NOT_REPRODUCED = "not_reproduced"
    BLOCKED_BY_ROE = "blocked_by_roe"
    NEEDS_MANUAL_FOLLOWUP = "needs_manual_followup"
    SKIPPED = "skipped"


def verification_result(status: VerificationStatus | str, next_best_manual_test: str, **details) -> dict:
    return {
        "status": VerificationStatus(status).value,
        "next_best_manual_test": next_best_manual_test,
        **details,
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _request(url: str, method: str = "GET", headers: dict | None = None, timeout: int = 8) -> dict:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "ARES verifier/1.0", **(headers or {})},
        method=method,
        data=b"" if method in {"PUT", "DELETE"} else None,
    )
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=_ctx()))
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(500).decode("utf-8", errors="ignore") if method != "HEAD" else ""
            return {"status_code": resp.status, "headers": dict(resp.headers), "body_preview": body}
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(500).decode("utf-8", errors="ignore")
        except Exception:
            pass
        return {"status_code": exc.code, "headers": dict(exc.headers or {}), "body_preview": body}
    except Exception as exc:
        return {"status_code": 0, "headers": {}, "body_preview": "", "error": str(exc)}


def _join(base_url: str, path: str) -> str:
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query.append((param, value))
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", urllib.parse.urlencode(query), ""))


def test_open_redirect(url: str, scope: ScopeValidator) -> dict:
    scope.assert_in_scope(url)
    tested = []
    for param in ("next", "url", "redirect", "return", "returnUrl", "continue"):
        test_url = _with_param(url, param, MARKER_URL)
        response = _request(test_url, method="GET")
        location = response.get("headers", {}).get("Location", "")
        confirmed = MARKER_HOST in location
        tested.append({"param": param, "status_code": response.get("status_code", 0), "location": location, "confirmed": confirmed})
        if confirmed:
            return verification_result(
                VerificationStatus.CONFIRMED,
                "Repeat the redirect with a researcher-controlled HTTPS endpoint and verify no sensitive query data is forwarded.",
                confirmed=True,
                tested_params=tested,
                status_code=response.get("status_code", 0),
                location=location,
            )
    return verification_result(
        VerificationStatus.NOT_REPRODUCED,
        "Review application-specific redirect parameter names and authenticated redirect flows manually.",
        confirmed=False,
        tested_params=tested,
        status_code=tested[-1]["status_code"] if tested else 0,
    )


def _is_file_creation_path(url: str) -> bool:
    path = urllib.parse.urlparse(url).path or "/"
    leaf = path.rstrip("/").rsplit("/", 1)[-1]
    return bool(leaf and ("." in leaf or leaf.startswith(".")))


def test_http_methods(
    url: str,
    scope: ScopeValidator,
    risky_methods: list[str] | tuple[str, ...] | None = None,
) -> dict:
    scope.assert_in_scope(url)
    methods = ["OPTIONS", "TRACE"]
    requested_risky = [method.upper() for method in (risky_methods or []) if method.upper() in {"PUT", "DELETE"}]
    skipped = [method for method in ("PUT", "DELETE") if method not in requested_risky]
    file_creation_path_blocked = bool(requested_risky and _is_file_creation_path(url))
    if not file_creation_path_blocked:
        methods.extend(requested_risky)
    else:
        skipped.extend(method for method in requested_risky if method not in skipped)
    results = {}
    for method in methods:
        response = _request(url, method=method)
        allow = response.get("headers", {}).get("Allow", "")
        results[method] = {
            "status_code": response.get("status_code", 0),
            "allow": allow,
            "request_body_bytes": 0 if method in {"PUT", "DELETE"} else None,
            "label": "method exposure check",
        }
    findings = []
    if results.get("TRACE", {}).get("status_code") and results["TRACE"]["status_code"] < 400:
        findings.append({"type": "trace_enabled", "severity": "MEDIUM"})
    for method in ("PUT", "DELETE"):
        if method in results and results[method]["status_code"] < 400:
            findings.append({"type": f"{method.lower()}_method_exposure", "severity": "LOW", "label": "method exposure check"})
    if findings:
        status = VerificationStatus.CONFIRMED
    elif any(item.get("status_code") for item in results.values()):
        status = VerificationStatus.NOT_REPRODUCED
    else:
        status = VerificationStatus.NEEDS_MANUAL_FOLLOWUP
    return verification_result(
        status,
        "Review the OPTIONS Allow header and repeat only explicitly authorized methods with an intercepting proxy; do not send a body.",
        methods=results,
        skipped_methods=list(dict.fromkeys(skipped)),
        findings=findings,
        risky_methods_enabled=bool(requested_risky) and not file_creation_path_blocked,
        file_creation_path_blocked=file_creation_path_blocked,
        label="method exposure check",
    )


def test_clickjacking(url: str, scope: ScopeValidator) -> dict:
    scope.assert_in_scope(url)
    response = _request(url, method="HEAD")
    if response.get("status_code", 0) == 0:
        response = _request(url, method="GET")
    headers = {k.lower(): v for k, v in response.get("headers", {}).items()}
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    confirmed = not xfo and not has_frame_ancestors
    return verification_result(
        VerificationStatus.CONFIRMED if confirmed else VerificationStatus.NOT_REPRODUCED,
        "Render the page in a same-origin-safe framing harness and confirm whether sensitive UI actions remain frameable.",
        confirmed=confirmed,
        status_code=response.get("status_code", 0),
        x_frame_options=xfo,
        csp_frame_ancestors=has_frame_ancestors,
    )


def test_host_header_injection(url: str, scope: ScopeValidator) -> dict:
    scope.assert_in_scope(url)
    response = _request(url, method="GET", headers={"Host": "evil.example.invalid"})
    location = response.get("headers", {}).get("Location", "")
    body = response.get("body_preview", "")
    reflected = "evil.example.invalid" in location or "evil.example.invalid" in body
    status = (
        VerificationStatus.CONFIRMED
        if "evil.example.invalid" in location
        else VerificationStatus.STRONGLY_INDICATED
        if reflected
        else VerificationStatus.NOT_REPRODUCED
    )
    return verification_result(
        status,
        "Repeat with X-Forwarded-Host and Forwarded headers through the authorized edge path and inspect absolute links and reset URLs.",
        reflected=reflected,
        explicit_reflection="evil.example.invalid" in location,
        manual_verification_needed=not ("evil.example.invalid" in location),
        status_code=response.get("status_code", 0),
        location=location,
    )


def enumerate_api_endpoints(base_url: str, scope: ScopeValidator) -> dict:
    scope.assert_in_scope(base_url)
    discovered = []
    for path in API_ENUM_PATHS[:API_ENUM_MAX_PATHS]:
        url = _join(base_url, path)
        valid, _ = scope.validate(url)
        if not valid:
            continue
        response = _request(url, method="GET")
        status = response.get("status_code", 0)
        exists = status in (200, 401, 403)
        if exists:
            discovered.append({"url": url, "path": path, "status_code": status, "endpoint_exists": True})
    return verification_result(
        VerificationStatus.CONFIRMED if discovered else VerificationStatus.NOT_REPRODUCED,
        "Review discovered API schemas and authenticated routes manually without attempting credentials.",
        base_url=base_url,
        discovered=discovered,
        paths_tested=min(API_ENUM_MAX_PATHS, len(API_ENUM_PATHS)),
    )


def discover_auth_panels(url: str, scope: ScopeValidator) -> dict:
    scope.assert_in_scope(url)
    found = []
    for path in AUTH_PANEL_PATHS:
        test_url = _join(url, path)
        response = _request(test_url, method="GET")
        if response.get("status_code") in (200, 401, 403):
            found.append({"path": path, "url": test_url, "status_code": response.get("status_code")})
    return verification_result(
        VerificationStatus.CONFIRMED if found else VerificationStatus.NOT_REPRODUCED,
        "Confirm the panel purpose and access controls manually; do not attempt default or discovered credentials.",
        accessible_panels=[item["path"] for item in found],
        panels=found,
        credential_attempts=0,
        manual_verification_needed=bool(found),
    )
