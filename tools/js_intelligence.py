"""
ARES — JavaScript Intelligence Extractor
Spiders a target web application, finds all JS files, and extracts:
  - API endpoints and routes
  - Hardcoded secrets (API keys, tokens, passwords)
  - Internal hostnames and IP addresses
  - AWS/cloud resource references
  - Authentication flows and JWT usage
  - GraphQL schemas
  - Hidden parameters and form fields

This is the #1 most underused recon technique — modern SPAs expose their
entire API surface in their bundled JavaScript.
"""

import hashlib
import logging
import re
import ssl
import time
import urllib.request
import urllib.parse
import urllib.error
from html.parser import HTMLParser
from utils.config import JS_INTEL_BUDGET
from utils.scope_validator import ScopeValidator


logger = logging.getLogger(__name__)

_MAX_FETCH_BYTES = 500_000
_MAX_REDIRECTS = 8
_SLOW_TARGET_SUFFIXES = ("vulnweb.com",)
JS_INTEL_TOTAL_BUDGET_S = JS_INTEL_BUDGET


# ── Regex patterns ────────────────────────────────────────────────────────────

# API endpoints — catches /api/v1/users, /auth/login, etc.
ENDPOINT_PATTERNS = [
    r'["\'`](/api/[a-zA-Z0-9/_\-\.]+)',
    r'["\'`](/v\d+/[a-zA-Z0-9/_\-\.]+)',
    r'["\'`](/graphql[a-zA-Z0-9/_\-\.]*)',
    r'["\'`](/auth/[a-zA-Z0-9/_\-\.]+)',
    r'["\'`](/admin/[a-zA-Z0-9/_\-\.]+)',
    r'["\'`](/internal/[a-zA-Z0-9/_\-\.]+)',
    r'["\'`](/rest/[a-zA-Z0-9/_\-\.]+)',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.[a-z]+\(["\']([^"\']+)["\']',
    r'\.get\(["\']([^"\']{5,80})["\']',
    r'\.post\(["\']([^"\']{5,80})["\']',
    r'baseURL[:\s=]+["\']([^"\']+)["\']',
    r'BASE_URL[:\s=]+["\']([^"\']+)["\']',
    r'API_URL[:\s=]+["\']([^"\']+)["\']',
]

# Secret patterns — catches keys, tokens, passwords
SECRET_PATTERNS = [
    (r'(?:api[_\-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,64})["\']', "API Key"),
    (r'(?:secret|SECRET)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,64})["\']', "Secret"),
    (r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', "Password"),
    (r'(?:token|TOKEN)\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', "Token"),
    (r'(?:aws_access_key_id|AWS_ACCESS_KEY_ID)\s*[=:]\s*["\']?(AKIA[A-Z0-9]{16})', "AWS Access Key"),
    (r'(AKIA[A-Z0-9]{16})', "AWS Access Key"),
    (r'(?:private_key|PRIVATE_KEY)["\']?\s*[=:]\s*["\']([^"\']{20,})["\']', "Private Key"),
    (r'Bearer\s+([a-zA-Z0-9_\-\.]{20,})', "Bearer Token"),
    (r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+', "JWT Token"),
    (r'(?:stripe|STRIPE)[_\-]?(?:key|KEY|secret|SECRET)\s*[=:]\s*["\']?(sk_(?:live|test)_[a-zA-Z0-9]{24,})', "Stripe Key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Token"),
    (r'glpat-[a-zA-Z0-9\-_]{20}', "GitLab Token"),
]

# Internal hostnames and IPs
INTERNAL_PATTERNS = [
    r'(?:https?://)((?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+)',
    r'(?:https?://)(localhost[:\d]*)',
    r'(?:https?://)([a-zA-Z0-9\-]+\.(?:internal|local|corp|intranet|lan))',
    r'(?:host|HOST|hostname|HOSTNAME)\s*[=:]\s*["\']([a-zA-Z0-9\.\-]+\.(?:internal|local|corp))["\']',
]

# Cloud resource references
CLOUD_PATTERNS = [
    (r'([a-zA-Z0-9\-]+\.s3\.amazonaws\.com)', "S3 Bucket"),
    (r's3://([a-zA-Z0-9\-\.]+)', "S3 Bucket"),
    (r'([a-zA-Z0-9\-]+\.blob\.core\.windows\.net)', "Azure Blob"),
    (r'([a-zA-Z0-9\-]+\.storage\.googleapis\.com)', "GCS Bucket"),
    (r'([a-zA-Z0-9\-]+\.cloudfront\.net)', "CloudFront"),
    (r'([a-zA-Z0-9\-]+\.execute-api\.[a-z0-9\-]+\.amazonaws\.com)', "AWS API Gateway"),
    (r'arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d+:[a-zA-Z0-9\-/]+', "AWS ARN"),
]


class ScriptTagParser(HTMLParser):
    """Extract script src URLs and inline JS from HTML."""
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.script_urls = []
        self.link_urls = []
        self.route_urls = []
        self.forms = []
        self.inline_scripts = []
        self._in_script = False
        self._current_script = []
        self._current_form = None

    def _remember_route(self, value: str):
        if not value:
            return
        full = urllib.parse.urljoin(self.base_url, value)
        if full not in self.route_urls:
            self.route_urls.append(full)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script":
            src = attrs.get("src", "")
            if src:
                full = urllib.parse.urljoin(self.base_url, src)
                if full not in self.script_urls:
                    self.script_urls.append(full)
            self._in_script = True
            self._current_script = []
        elif tag == "link":
            rel = (attrs.get("rel", "") or "").lower()
            href = attrs.get("href", "")
            if href and (href.endswith(".js") or "modulepreload" in rel or "preload" in rel or "prefetch" in rel):
                full = urllib.parse.urljoin(self.base_url, href)
                if full not in self.link_urls:
                    self.link_urls.append(full)
        elif tag == "form":
            action = attrs.get("action", "") or self.base_url
            self._current_form = {
                "method": (attrs.get("method", "GET") or "GET").upper(),
                "action": urllib.parse.urljoin(self.base_url, action),
                "fields": [],
            }
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = attrs.get("name", "") or attrs.get("id", "")
            if name and name not in self._current_form["fields"]:
                self._current_form["fields"].append(name)
        for attr_name in ("href", "action", "formaction", "data-url", "data-endpoint", "data-api", "data-href"):
            value = attrs.get(attr_name, "")
            if value:
                self._remember_route(value)

    def handle_endtag(self, tag):
        if tag == "script":
            if self._current_script:
                self.inline_scripts.append("".join(self._current_script))
            self._in_script = False
            self._current_script = []
        elif tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data):
        if self._in_script:
            self._current_script.append(data)


def _fetch(url: str, timeout: int = 10) -> str:
    """Fetch URL with bounded redirects, return text content or empty string."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    def _urlopen_no_redirect(req: urllib.request.Request):
        opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
        return opener.open(req, timeout=timeout)

    current = url
    visited: set[str] = set()
    redirects = 0

    while True:
        if current in visited:
            logger.warning("js_intelligence: redirect loop detected for %r", current)
            return ""
        visited.add(current)

        parsed = urllib.parse.urlparse(current)
        if parsed.scheme not in ("http", "https"):
            return ""

        req = urllib.request.Request(current, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "*/*"
        })

        try:
            with _urlopen_no_redirect(req) as resp:
                ct = resp.headers.get("Content-Type", "")
                if "text" not in ct and "javascript" not in ct and "json" not in ct:
                    return ""
                clen = resp.headers.get("Content-Length")
                try:
                    if clen is not None and int(clen) > _MAX_FETCH_BYTES:
                        logger.warning("js_intelligence: content too large (%s bytes) for %r; truncating", clen, current)
                except Exception:
                    pass
                return resp.read(_MAX_FETCH_BYTES).decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            code = int(getattr(e, "code", 0) or 0)
            if 300 <= code < 400:
                loc = e.headers.get("Location") if getattr(e, "headers", None) else None
                if not loc:
                    return ""
                current_scheme = urllib.parse.urlparse(current).scheme
                next_url = urllib.parse.urljoin(current, loc)
                next_scheme = urllib.parse.urlparse(next_url).scheme
                if current_scheme == "https" and next_scheme == "http":
                    return ""
                redirects += 1
                if redirects > _MAX_REDIRECTS:
                    logger.warning("js_intelligence: max redirects exceeded for %r", url)
                    return ""
                current = next_url
                continue
            return ""
        except Exception:
            return ""


_STATIC_ASSET_EXTENSIONS = (
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".map", ".mp4", ".webm", ".mp3", ".pdf", ".zip"
)


def _normalize_route(value: str, base_url: str) -> str | None:
    value = (value or "").strip()
    if not value or value.startswith(("#", "javascript:", "mailto:", "tel:")):
        return None
    full = urllib.parse.urljoin(base_url, value)
    parsed = urllib.parse.urlparse(full)
    if parsed.scheme not in ("http", "https"):
        return None
    path = parsed.path or "/"
    lower_path = path.lower()
    if any(lower_path.endswith(ext) for ext in _STATIC_ASSET_EXTENSIONS):
        return None
    if parsed.query:
        return path + "?" + parsed.query
    return path


def _extract_html_routes(html: str, base_url: str) -> list[str]:
    parser = ScriptTagParser(base_url)
    parser.feed(html)

    routes = []
    for raw in parser.route_urls:
        route = _normalize_route(raw, base_url)
        if route:
            routes.append(route)

    for match in re.finditer(r'["\']([^"\']+\.(?:jsp|php|asp|aspx|do|action)(?:\?[^"\']*)?)["\']', html, re.IGNORECASE):
        route = _normalize_route(match.group(1), base_url)
        if route:
            routes.append(route)

    for match in re.finditer(r'["\'](/[^"\']+\?[^"\']+)["\']', html, re.IGNORECASE):
        route = _normalize_route(match.group(1), base_url)
        if route:
            routes.append(route)

    return sorted(dict.fromkeys(routes))


def _extract_html_forms(html: str, base_url: str) -> list[dict]:
    parser = ScriptTagParser(base_url)
    parser.feed(html)
    forms = []
    seen = set()
    for form in parser.forms:
        action = form.get("action", base_url)
        route = _normalize_route(action, base_url)
        if not route:
            continue
        key = (form.get("method", "GET"), route, tuple(form.get("fields", [])))
        if key in seen:
            continue
        seen.add(key)
        forms.append({
            "method": form.get("method", "GET"),
            "action": route,
            "fields": form.get("fields", []),
        })
    return forms


def _host_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc or parsed.path or url
    return host.split("/", 1)[0].rstrip("/").lower()


def _is_slow_target(url: str) -> bool:
    host = _host_from_url(url)
    return any(host == suffix or host.endswith("." + suffix) for suffix in _SLOW_TARGET_SUFFIXES)


def _analyze_js(js_content: str, source_url: str = "") -> dict:
    """Run all pattern analysis on a JS string. Returns findings dict."""
    findings = {
        "endpoints": set(),
        "secrets": [],
        "internal_hosts": set(),
        "cloud_resources": [],
        "has_graphql": False,
        "has_jwt": False,
        "source": source_url
    }

    # Endpoints
    for pattern in ENDPOINT_PATTERNS:
        for m in re.finditer(pattern, js_content):
            ep = m.group(1)
            if len(ep) > 3 and not ep.startswith("//"):
                findings["endpoints"].add(ep)

    # Secrets — deduplicate by value (hashed; avoid retaining full secrets in-memory)
    seen_secrets = set()
    for pattern, label in SECRET_PATTERNS:
        for m in re.finditer(pattern, js_content, re.IGNORECASE):
            val = m.group(1) if m.lastindex else m.group(0)
            if len(val) <= 8:
                continue
            fp = hashlib.sha1(val.encode("utf-8", errors="ignore")).hexdigest()
            if fp in seen_secrets:
                continue
            seen_secrets.add(fp)
            # Partially redact for report safety
            redacted = val[:4] + "..." + val[-4:] if len(val) > 12 else val[:4] + "..."
            findings["secrets"].append({
                "type": label,
                "value_preview": redacted,
                "full_length": len(val),
                "severity": "CRITICAL" if label in ("AWS Access Key", "Private Key", "Stripe Key") else "HIGH"
            })

    # Internal hosts
    for pattern in INTERNAL_PATTERNS:
        for m in re.finditer(pattern, js_content, re.IGNORECASE):
            findings["internal_hosts"].add(m.group(1))

    # Cloud resources
    seen_cloud = set()
    for pattern, label in CLOUD_PATTERNS:
        for m in re.finditer(pattern, js_content, re.IGNORECASE):
            val = m.group(1) if m.lastindex else m.group(0)
            if val not in seen_cloud:
                seen_cloud.add(val)
                findings["cloud_resources"].append({"type": label, "value": val})

    # Feature flags
    findings["has_graphql"] = bool(re.search(r'graphql|gql`|useQuery|useMutation', js_content, re.IGNORECASE))
    findings["has_jwt"] = bool(re.search(r'eyJ[a-zA-Z0-9]|jwt|Bearer', js_content, re.IGNORECASE))

    # Convert sets to lists for JSON serialization
    findings["endpoints"] = sorted(findings["endpoints"])
    findings["internal_hosts"] = sorted(findings["internal_hosts"])

    return findings


def _candidate_page_urls(url: str, fallback_urls: list[str] | None = None) -> list[str]:
    urls = [url]
    if fallback_urls:
        urls.extend(fallback_urls)
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme and parsed.netloc:
        base = f"{parsed.scheme}://{parsed.netloc}"
        urls.extend([base, base + "/", base + "/index.php", base + "/index.html"])
    seen = set()
    out = []
    for item in urls:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _collect_script_urls(html: str, base_url: str) -> tuple[list[str], list[str]]:
    parser = ScriptTagParser(base_url)
    parser.feed(html)
    extra_urls = []
    for match in re.finditer(r'["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html, re.IGNORECASE):
        full = urllib.parse.urljoin(base_url, match.group(1))
        extra_urls.append(full)
    script_urls = []
    seen = set()
    for item in parser.script_urls + parser.link_urls + extra_urls:
        if item in seen:
            continue
        seen.add(item)
        script_urls.append(item)
    return script_urls, parser.inline_scripts


def _absolute_page_url(base_url: str, route: str) -> str:
    if route.startswith("http://") or route.startswith("https://"):
        return route
    return urllib.parse.urljoin(base_url, route)


def _crawl_html_surface(
    start_url: str,
    scope: ScopeValidator,
    seed_html: str = "",
    fallback_urls: list[str] | None = None,
    max_pages: int = 12,
    max_depth: int = 2,
    timeout: int = 10,
    started_at: float | None = None,
) -> dict:
    """Bounded same-scope crawler for passive route, form, and script discovery."""
    started_at = started_at or time.monotonic()
    queue = []
    if seed_html:
        queue.append((start_url, 0, seed_html))
    else:
        for candidate in _candidate_page_urls(start_url, fallback_urls):
            if candidate not in [item[0] for item in queue]:
                queue.append((candidate, 0, ""))

    seen_urls = set()
    pages = []
    routes = set()
    forms = []
    script_urls = []
    inline_scripts = []
    page_candidates = []

    while queue and len(pages) < max_pages:
        if time.monotonic() - started_at >= JS_INTEL_TOTAL_BUDGET_S:
            break
        page_url, depth, known_html = queue.pop(0)
        if page_url in seen_urls:
            continue
        seen_urls.add(page_url)
        valid, _ = scope.validate(page_url)
        if not valid:
            continue
        page_candidates.append(page_url)

        html = known_html or _fetch(page_url, timeout=timeout)
        if not html:
            continue

        page_routes = _extract_html_routes(html, page_url)
        page_forms = _extract_html_forms(html, page_url)
        page_scripts, page_inline = _collect_script_urls(html, page_url)

        for route in page_routes:
            routes.add(route)
        for form in page_forms:
            if form not in forms:
                forms.append(form)
                routes.add(form["action"])
        for script_url in page_scripts:
            if script_url not in script_urls:
                script_urls.append(script_url)
        inline_scripts.extend(page_inline)

        pages.append({
            "url": page_url,
            "depth": depth,
            "routes": len(page_routes),
            "forms": len(page_forms),
            "scripts": len(page_scripts),
        })

        if depth >= max_depth:
            continue
        for route in page_routes:
            next_url = _absolute_page_url(page_url, route)
            if next_url in seen_urls:
                continue
            valid, _ = scope.validate(next_url)
            if valid:
                queue.append((next_url, depth + 1, ""))

    return {
        "pages": pages,
        "routes": sorted(routes),
        "forms": forms,
        "script_urls": script_urls,
        "inline_scripts": inline_scripts,
        "page_candidates": page_candidates,
    }


def js_intelligence(url: str, scope: ScopeValidator, max_scripts: int = 8, seed_html: str = "", fallback_urls: list[str] | None = None) -> dict:
    """
    Full JS intelligence extraction:
    1. Fetch the page HTML
    2. Find all <script src="..."> URLs and inline scripts
    3. Fetch each external JS file
    4. Run pattern analysis across all JS content
    5. Return aggregated findings
    """
    scope.assert_in_scope(url)
    started_at = time.monotonic()
    page_fetch_timeout = 20 if _is_slow_target(url) else 10
    script_fetch_timeout = 25 if _is_slow_target(url) else 15

    crawl = _crawl_html_surface(
        url,
        scope,
        seed_html=seed_html,
        fallback_urls=fallback_urls,
        timeout=page_fetch_timeout,
        started_at=started_at,
    )
    if not crawl["pages"]:
        return {"url": url, "error": "Could not fetch page", "endpoints": [],
                "secrets": [], "internal_hosts": [], "cloud_resources": [], "script_count": 0,
                "forms": [], "form_count": 0, "pages_crawled": [],
                "page_candidates": crawl["page_candidates"] or _candidate_page_urls(url, fallback_urls),
                "timeout_profile": {"page_fetch_timeout": page_fetch_timeout, "script_fetch_timeout": script_fetch_timeout}}

    fetch_source_url = crawl["pages"][0]["url"]
    script_urls = crawl["script_urls"]
    inline_scripts = crawl["inline_scripts"]
    html_routes = crawl["routes"]

    all_findings = {
        "url": url,
        "page_url": fetch_source_url,
        "endpoints": set(html_routes),
        "secrets": [],
        "internal_hosts": set(),
        "cloud_resources": [],
        "has_graphql": False,
        "has_jwt": False,
        "scripts_analyzed": [],
        "script_count": 0,
        "html_routes": html_routes,
        "forms": crawl["forms"],
        "form_count": len(crawl["forms"]),
        "pages_crawled": crawl["pages"],
        "page_candidates": crawl["page_candidates"] or [fetch_source_url],
        "timeout_profile": {"page_fetch_timeout": page_fetch_timeout, "script_fetch_timeout": script_fetch_timeout},
    }

    # Analyze inline scripts
    for inline_idx, inline in enumerate(inline_scripts):
        if len(inline.strip()) < 50:
            continue
        f = _analyze_js(inline, source_url=f"[inline:{inline_idx}]")
        all_findings["endpoints"].update(f["endpoints"])
        all_findings["secrets"].extend(f["secrets"])
        all_findings["internal_hosts"].update(f["internal_hosts"])
        all_findings["cloud_resources"].extend(f["cloud_resources"])
        all_findings["has_graphql"] = all_findings["has_graphql"] or f["has_graphql"]
        all_findings["has_jwt"] = all_findings["has_jwt"] or f["has_jwt"]

    # Fetch and analyze external scripts (limit to max_scripts)
    seen_secrets_vals = set()
    for script_url in script_urls[:max_scripts]:
        if time.monotonic() - started_at >= JS_INTEL_TOTAL_BUDGET_S:
            break
        valid, _ = scope.validate(script_url)
        if not valid:
            continue
        js_content = _fetch(script_url, timeout=script_fetch_timeout)
        if not js_content:
            continue

        f = _analyze_js(js_content, source_url=script_url)
        all_findings["endpoints"].update(f["endpoints"])
        all_findings["has_graphql"] = all_findings["has_graphql"] or f["has_graphql"]
        all_findings["has_jwt"] = all_findings["has_jwt"] or f["has_jwt"]
        all_findings["internal_hosts"].update(f["internal_hosts"])
        all_findings["cloud_resources"].extend(f["cloud_resources"])

        # Deduplicate secrets across scripts
        for s in f["secrets"]:
            key = (s.get("type"), s.get("value_preview"), s.get("full_length"), script_url)
            if key not in seen_secrets_vals:
                seen_secrets_vals.add(key)
                all_findings["secrets"].append(s)

        all_findings["scripts_analyzed"].append(script_url)
        all_findings["script_count"] += 1

    # Convert sets to sorted lists
    all_findings["endpoints"] = sorted(all_findings["endpoints"])
    all_findings["internal_hosts"] = sorted(all_findings["internal_hosts"])

    return all_findings
