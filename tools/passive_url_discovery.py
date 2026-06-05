"""
Passive URL discovery for ARES.

This module intentionally fetches only standards-based discovery files and
never executes search dorks, follows redirects, or brute-forces paths.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from utils.config import (
    PASSIVE_URL_MAX,
    PASSIVE_URL_TIMEOUT,
    SITEMAP_MAX_CHILDREN,
)
from utils.scope_validator import ScopeValidator


_MAX_FETCH_BYTES = 1_000_000
_SECURITY_TXT_FIELDS = {
    "contact",
    "policy",
    "hiring",
    "encryption",
    "acknowledgments",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _empty_result(base_url: str) -> dict:
    return {
        "base_url": base_url,
        "robots": {"status_code": 0, "allow": [], "disallow": [], "urls": []},
        "sitemaps": {"status_code": 0, "urls": [], "child_sitemaps": []},
        "security_txt": {"status_code": 0, "fields": {}},
        "discovered_urls": [],
        "suggested_dorks": [],
        "coverage": {},
    }


def _normalize_base_url(base_url: str) -> str:
    base_url = (base_url or "").strip()
    if not base_url:
        return ""
    if "://" not in base_url:
        base_url = f"https://{base_url}"
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return base_url
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def _origin(base_url: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def _fetch_text(url: str, timeout: float) -> tuple[int, str, str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ARES passive-url-discovery/1.0",
            "Accept": "text/plain,application/xml,text/xml,*/*",
        },
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = int(getattr(resp, "status", getattr(resp, "code", 0)) or 0)
            body = resp.read(_MAX_FETCH_BYTES).decode("utf-8", errors="ignore")
            return status, body, ""
    except urllib.error.HTTPError as exc:
        status = int(getattr(exc, "code", 0) or 0)
        body = ""
        try:
            body = exc.read(_MAX_FETCH_BYTES).decode("utf-8", errors="ignore")
        except Exception:
            pass
        return status, body, f"http_{status}" if status else "http_error"
    except Exception as exc:
        return 0, "", type(exc).__name__.lower()


def _dedupe(items: list[str], limit: int | None = None) -> list[str]:
    out = []
    seen = set()
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
        if limit is not None and len(out) >= limit:
            break
    return out


def _in_scope_absolute(base_url: str, value: str, scope: ScopeValidator) -> str | None:
    value = (value or "").strip()
    if not value or value.startswith(("#", "mailto:", "tel:", "javascript:")):
        return None
    absolute = urllib.parse.urljoin(base_url, value)
    parsed = urllib.parse.urlparse(absolute)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    clean = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))
    valid, _ = scope.validate(clean)
    return clean if valid else None


def _parse_robots(base_url: str, body: str, scope: ScopeValidator) -> dict:
    allow = []
    disallow = []
    for line in body.splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key not in ("allow", "disallow") or not value:
            continue
        absolute = _in_scope_absolute(base_url, value, scope)
        if not absolute:
            continue
        if key == "allow":
            allow.append(absolute)
        else:
            disallow.append(absolute)
    allow = _dedupe(allow, PASSIVE_URL_MAX)
    disallow = _dedupe(disallow, PASSIVE_URL_MAX)
    return {"allow": allow, "disallow": disallow, "urls": _dedupe(allow + disallow, PASSIVE_URL_MAX)}


def _xml_items(root: ET.Element, local_name: str) -> list[str]:
    values = []
    for elem in root.iter():
        if elem.tag.rsplit("}", 1)[-1] == local_name and elem.text:
            values.append(elem.text.strip())
    return values


def _parse_sitemap_urls(base_url: str, body: str, scope: ScopeValidator) -> tuple[list[str], list[str]]:
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return [], []

    tag = root.tag.rsplit("}", 1)[-1].lower()
    urls = []
    child_sitemaps = []
    if tag == "urlset":
        for loc in _xml_items(root, "loc"):
            absolute = _in_scope_absolute(base_url, loc, scope)
            if absolute:
                urls.append(absolute)
    elif tag == "sitemapindex":
        for loc in _xml_items(root, "loc"):
            absolute = _in_scope_absolute(base_url, loc, scope)
            if absolute:
                child_sitemaps.append(absolute)
    return _dedupe(urls, PASSIVE_URL_MAX), _dedupe(child_sitemaps, SITEMAP_MAX_CHILDREN)


def _parse_security_txt(body: str) -> dict:
    fields: dict[str, list[str]] = {}
    for line in body.splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key not in _SECURITY_TXT_FIELDS or not value:
            continue
        fields.setdefault(key, [])
        if value not in fields[key]:
            fields[key].append(value)
    return fields


def _suggested_dorks(base_url: str) -> list[str]:
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname or parsed.netloc or base_url
    return [
        f"site:{host} filetype:pdf",
        f"site:{host} inurl:login",
        f"site:{host} inurl:admin",
        f"site:{host} inurl:api",
        f"site:{host} intitle:index.of",
        f"site:{host} ext:sql OR ext:bak OR ext:zip",
        f"site:{host} \"api_key\" OR \"token\" OR \"secret\"",
    ]


def passive_url_discovery(base_url: str, scope: ScopeValidator) -> dict:
    """Discover passive URL evidence from robots.txt, sitemap.xml, and security.txt."""
    normalized_base = _normalize_base_url(base_url)
    scope.assert_in_scope(normalized_base)
    result = _empty_result(normalized_base)
    result["suggested_dorks"] = _suggested_dorks(normalized_base)

    base_origin = _origin(normalized_base)
    coverage = {}

    robots_url = urllib.parse.urljoin(base_origin + "/", "robots.txt")
    status, body, error = _fetch_text(robots_url, PASSIVE_URL_TIMEOUT)
    result["robots"]["status_code"] = status
    coverage["robots_txt"] = {"status": "success" if status == 200 else "failed", "error": error}
    if status == 200 and body:
        parsed_robots = _parse_robots(base_origin + "/", body, scope)
        result["robots"].update(parsed_robots)

    sitemap_url = urllib.parse.urljoin(base_origin + "/", "sitemap.xml")
    status, body, error = _fetch_text(sitemap_url, PASSIVE_URL_TIMEOUT)
    result["sitemaps"]["status_code"] = status
    coverage["sitemap_xml"] = {"status": "success" if status == 200 else "failed", "error": error}
    sitemap_urls = []
    child_sitemaps = []
    if status == 200 and body:
        sitemap_urls, child_sitemaps = _parse_sitemap_urls(base_origin + "/", body, scope)
        result["sitemaps"]["child_sitemaps"] = child_sitemaps
        for child_url in child_sitemaps[:SITEMAP_MAX_CHILDREN]:
            child_status, child_body, child_error = _fetch_text(child_url, PASSIVE_URL_TIMEOUT)
            coverage.setdefault("child_sitemaps", []).append({
                "url": child_url,
                "status_code": child_status,
                "status": "success" if child_status == 200 else "failed",
                "error": child_error,
            })
            if child_status == 200 and child_body:
                child_urls, _ = _parse_sitemap_urls(child_url, child_body, scope)
                sitemap_urls.extend(child_urls)
        result["sitemaps"]["urls"] = _dedupe(sitemap_urls, PASSIVE_URL_MAX)

    security_url = urllib.parse.urljoin(base_origin + "/", ".well-known/security.txt")
    status, body, error = _fetch_text(security_url, PASSIVE_URL_TIMEOUT)
    result["security_txt"]["status_code"] = status
    coverage["security_txt"] = {"status": "success" if status == 200 else "failed", "error": error}
    if status == 200 and body:
        result["security_txt"]["fields"] = _parse_security_txt(body)

    result["discovered_urls"] = _dedupe(
        result["robots"]["urls"] + result["sitemaps"]["urls"],
        PASSIVE_URL_MAX,
    )
    coverage["suggested_dorks"] = {"status": "generated_not_executed", "count": len(result["suggested_dorks"])}
    result["coverage"] = coverage
    return result
