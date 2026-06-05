"""
ARES Tool Library — Network & OSINT (v3)
- Tech fingerprinting from Server header, X-Powered-By, cookies, HTML body
- CPE strings with version numbers for NVD CVE lookup
- Tries https then http fallback
- Expanded misconfig path list
"""

import socket
import subprocess
import json
import ipaddress
import os
import urllib.request
import urllib.error
import urllib.parse
import ssl
import re
import time
import xml.etree.ElementTree as ET

from utils.config import (
    HTTP_PROBE_CURL_TIMEOUT as HTTP_PROBE_CURL_TIMEOUT_S,
    HTTP_PROBE_HEAD_TIMEOUT as HTTP_PROBE_HEAD_TIMEOUT_S,
    HTTP_PROBE_MAX_BODY_BYTES,
    HTTP_PROBE_TIMEOUT as HTTP_PROBE_TIMEOUT_S,
    HTTP_PROBE_TOTAL_BUDGET as HTTP_PROBE_TOTAL_BUDGET_S,
    EVIDENCE_PREVIEW_MAX_CHARS,
    MISCONFIG_TIMEOUT as MISCONFIG_REQUEST_TIMEOUT_S,
    MISCONFIG_TOTAL_BUDGET as MISCONFIG_TOTAL_BUDGET_S,
    VERSION_DISCLOSURE_TIMEOUT,
)
from utils.scope_validator import ScopeValidator


# ── Tech fingerprint patterns ─────────────────────────────────────────────────
# (regex, display_label, cpe_vendor, cpe_product)
TECH_PATTERNS = [
    (r"Apache(?: httpd)?[/ ]([\d.]+)", "Apache {v}",   "apache",        "http_server"),
    (r"Apache Tomcat(?:/Coyote(?: JSP engine)?)?[/ ]?([\d.]*)", "Apache Tomcat {v}", "apache", "tomcat"),
    (r"nginx[/ ]([\d.]+)",          "nginx {v}",       "nginx",         "nginx"),
    (r"Microsoft-IIS[/ ]([\d.]+)",  "IIS {v}",         "microsoft",     "iis"),
    (r"LiteSpeed[/ ]([\d.]+)",      "LiteSpeed {v}",   "litespeed",     "litespeed_web_server"),
    (r"PHP[/ ]([\d.]+)",            "PHP {v}",         "php",           "php"),
    (r"ASP\.NET[/ ]?([\d.]+)",      "ASP.NET {v}",     "microsoft",     "asp.net"),
    (r"Express[/ ]?([\d.]+)",       "Express {v}",     "expressjs",     "express"),
    (r"Django[/ ]?([\d.]+)",        "Django {v}",      "djangoproject", "django"),
    (r"Rails[/ ]?([\d.]+)",         "Rails {v}",       "rubyonrails",   "ruby_on_rails"),
    (r"wp-content",                 "WordPress",       "wordpress",     "wordpress"),
    (r"WordPress[/ ]?([\d.]+)",     "WordPress {v}",   "wordpress",     "wordpress"),
    (r"Drupal[/ ]?([\d.]+)",        "Drupal {v}",      "drupal",        "drupal"),
    (r"Joomla[/ !]?([\d.]+)",       "Joomla {v}",      "joomla",        "joomla"),
    (r"jquery[/ v\-]([\d.]+)",      "jQuery {v}",      "jquery",        "jquery"),
    (r"bootstrap[/ v\-]([\d.]+)",   "Bootstrap {v}",   "getbootstrap",  "bootstrap"),
    (r"cloudflare",                 "Cloudflare",      None,            None),
    (r"openssl[/ ]([\d.]+)",        "OpenSSL {v}",     "openssl",       "openssl"),
]

HTTP_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
HTTP_ACCEPT = "text/html,application/xhtml+xml,*/*"
PROBE_ENTRYPOINTS = ("", "/", "/index.php", "/index.html", "/default.aspx")
SLOW_TARGET_SUFFIXES = ("vulnweb.com",)
LOOPBACK_WEB_PORTS = (8080, 3000)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.IGNORECASE)
FALLBACK_SUBDOMAIN_WORDLIST = [
    "www", "mail", "api", "admin", "login", "auth", "app", "dev",
    "staging", "test", "portal", "vpn", "docs", "support", "cdn",
]
VERSION_DISCLOSURE_PATHS = (
    "/CHANGELOG.md",
    "/readme.txt",
    "/readme.html",
    "/version.txt",
    "/build-info",
    "/.well-known/security.txt",
    "/server-status",
    "/server-info",
    "/actuator/health",
    "/actuator/env",
    "/actuator/mappings",
    "/actuator/beans",
    "/telescope",
    "/horizon",
    "/admin",
    "/wp-admin/",
    "/wp-json/",
    "/phpinfo.php",
)
SECRET_REDACTIONS = (
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"Bearer\s+[A-Za-z0-9._\-]{16,}", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{16,}"), "[REDACTED_STRIPE_KEY]"),
    (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s,&<]{4,}"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"]?[^'\"\s,&<]{8,}"), r"\1=[REDACTED]"),
)
SENSITIVE_BODY_MARKERS = (
    "aws_access_key_id",
    "secret_access_key",
    "api_key",
    "apikey",
    "password",
    "passwd",
    "bearer ",
    "ghp_",
    "sk_live_",
    "database_url",
    "jdbc:",
)


def _extract_tech(text: str) -> list:
    found = []
    seen = set()
    for pattern, label, vendor, product in TECH_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if not m:
            continue
        version = m.group(1) if m.lastindex and m.group(1) else ""
        name = label.replace("{v}", version).strip()
        key = name.split(" ")[0].lower()
        if key in seen:
            continue
        seen.add(key)
        entry = {"name": name, "version": version}
        if vendor and product:
            entry["cpe"] = f"{vendor}:{product}:{version}" if version else f"{vendor}:{product}"
        found.append(entry)
    return found


def _cpe_strings(tech_list: list) -> list:
    return _unique([t["cpe"] for t in tech_list if t.get("cpe")])


def _cpe23(vendor: str, product: str, version: str) -> str:
    version = version or "*"
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _candidate_cpes_for_service(product: str, version: str, service: str = "", extrainfo: str = "") -> list[str]:
    haystack = " ".join([product or "", service or "", extrainfo or ""]).lower()
    mappings = (
        (("apache httpd", "apache http server"), ("apache", "http_server")),
        (("nginx",), ("nginx", "nginx")),
        (("openssl",), ("openssl", "openssl")),
        (("apache tomcat", "tomcat"), ("apache", "tomcat")),
        (("microsoft iis", "microsoft-iis", "iis"), ("microsoft", "internet_information_services")),
        (("php",), ("php", "php")),
        (("openssh", "open ssh"), ("openbsd", "openssh")),
        (("postfix",), ("postfix", "postfix")),
        (("exim",), ("exim", "exim")),
        (("mysql",), ("mysql", "mysql")),
        (("postgresql", "postgres"), ("postgresql", "postgresql")),
    )
    out = []
    for needles, (vendor, cpe_product) in mappings:
        if any(needle in haystack for needle in needles):
            out.append(_cpe23(vendor, cpe_product, version))
    return out


def parse_service_banners(nmap_xml: str) -> list[dict]:
    """Parse nmap XML service records into structured inventory with CPE candidates."""
    try:
        root = ET.fromstring(nmap_xml or "")
    except ET.ParseError:
        return []

    inventory = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is not None and state.get("state") and state.get("state") != "open":
            continue
        service = port.find("service")
        portid = port.get("portid", "")
        try:
            port_num = int(portid)
        except (TypeError, ValueError):
            continue
        protocol = port.get("protocol", "")
        service_name = service.get("name", "") if service is not None else ""
        product = service.get("product", "") if service is not None else ""
        version = service.get("version", "") if service is not None else ""
        extrainfo = service.get("extrainfo", "") if service is not None else ""
        tunnel = service.get("tunnel", "") if service is not None else ""
        candidate_cpes = _candidate_cpes_for_service(product, version, service_name, extrainfo)
        if candidate_cpes and version:
            confidence = "HIGH"
        elif product:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        inventory.append({
            "port": port_num,
            "protocol": protocol,
            "service": service_name,
            "product": product,
            "version": version,
            "extrainfo": extrainfo,
            "tunnel": tunnel,
            "candidate_cpes": candidate_cpes,
            "confidence": confidence,
        })
    return inventory


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _urlopen_no_redirect(req: urllib.request.Request, timeout: int | float, ctx: ssl.SSLContext):
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
    return opener.open(req, timeout=timeout)


def _build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Some legacy demo targets negotiate only with older cipher profiles.
    if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
        ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    except ssl.SSLError:
        pass
    return ctx


def _is_tls_handshake_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(token in text for token in (
        "handshake failure",
        "sslv3_alert_handshake_failure",
        "tlsv1 alert",
        "unsupported protocol",
        "wrong version number",
    ))


def _unique(seq):
    out = []
    seen = set()
    for item in seq:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def redact_email(email: str) -> str:
    email = (email or "").strip()
    if "@" not in email:
        return email
    local, domain = email.split("@", 1)
    prefix = local[:2]
    return f"{prefix}***@{domain.lower()}"


def _parse_whois_org_osint(text: str, fields: dict | None = None) -> dict:
    fields = fields or {}
    organization = (
        fields.get("Registrant Organization")
        or fields.get("OrgName")
        or fields.get("Organization")
        or fields.get("Registrant Org")
        or ""
    )
    registrar = fields.get("Registrar") or fields.get("Sponsoring Registrar") or ""
    emails = []
    abuse_emails = []

    for line in text.splitlines():
        clean = line.strip()
        if not clean:
            continue
        if ":" in clean:
            key, value = clean.split(":", 1)
            norm_key = key.strip().lower()
            value = value.strip()
            if not organization and norm_key in {
                "orgname",
                "organization",
                "registrant organization",
                "registrant org",
            }:
                organization = value
            if not registrar and norm_key in {"registrar", "sponsoring registrar"}:
                registrar = value
        else:
            norm_key = ""
        found_emails = [m.group(0).lower() for m in EMAIL_RE.finditer(clean)]
        if not found_emails:
            continue
        if "abuse" in norm_key or "abuse" in clean.lower():
            abuse_emails.extend(found_emails)
        elif any(token in norm_key for token in ("admin", "tech", "registrant", "contact", "email")):
            emails.extend(found_emails)

    return {
        "organization": organization,
        "registrar": registrar,
        "emails": _unique(emails),
        "abuse_emails": _unique(abuse_emails),
        "source": "whois",
    }


def redact_org_osint(org_osint: dict) -> dict:
    return {
        "organization": org_osint.get("organization", ""),
        "registrar": org_osint.get("registrar", ""),
        "emails": [redact_email(email) for email in org_osint.get("emails", [])],
        "abuse_emails": [redact_email(email) for email in org_osint.get("abuse_emails", [])],
        "source": org_osint.get("source", "whois"),
    }


def _normalize_probe_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or ""
    if path == "/":
        path = ""
    return urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        path,
        parsed.params,
        parsed.query,
        "",
    ))


def _build_probe_candidates(url: str) -> list[str]:
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.rstrip("/")
    if not domain:
        return [url]

    schemes = ["https", "http"] if (parsed.scheme or "https") == "https" else ["http", "https"]
    if _is_slow_target(domain):
        schemes = ["http", "https"]
    current_path = parsed.path or ""
    paths = [current_path] if current_path not in ("", "/") else list(PROBE_ENTRYPOINTS)

    host = parsed.hostname or domain.split(":", 1)[0]
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = host.lower() == "localhost"

    candidates = []
    if is_loopback and ":" not in domain:
        for port in LOOPBACK_WEB_PORTS:
            base = f"http://{domain}:{port}"
            for path in paths:
                if path in ("", "/"):
                    candidates.append(base)
                else:
                    candidates.append(base + path)

    for scheme in schemes:
        base = f"{scheme}://{domain}"
        for path in paths:
            if path in ("", "/"):
                candidates.append(base)
            else:
                candidates.append(base + path)
    return _unique(candidates)


def _host_from_target(target: str) -> str:
    parsed = urllib.parse.urlparse(target)
    host = parsed.netloc or parsed.path or target
    return host.split("/", 1)[0].rstrip("/").lower()


def _is_slow_target(target: str) -> bool:
    host = _host_from_target(target)
    return any(host == suffix or host.endswith("." + suffix) for suffix in SLOW_TARGET_SUFFIXES)


def _resolve_wordlist_path(path: str) -> str:
    if os.path.isabs(path):
        return path
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(repo_root, path)


def load_subdomain_wordlist(path: str, max_words: int) -> list[str]:
    """Load, normalize, dedupe, and cap subdomain candidates."""
    limit = max(int(max_words or 0), 1)
    resolved = _resolve_wordlist_path(path)
    words = []
    try:
        with open(resolved, "r", encoding="utf-8") as f:
            for line in f:
                word = line.strip().lower()
                if not word or word.startswith("#"):
                    continue
                if word not in words:
                    words.append(word)
                if len(words) >= limit:
                    break
    except OSError:
        words = []
        for word in FALLBACK_SUBDOMAIN_WORDLIST:
            word = word.strip().lower()
            if word and word not in words:
                words.append(word)
            if len(words) >= limit:
                break
    return words


def subdomain_wordlist_source(path: str) -> str:
    resolved = _resolve_wordlist_path(path)
    return path if os.path.exists(resolved) else "internal fallback"


def _normalize_base_url(base_url: str) -> str:
    base_url = (base_url or "").strip()
    if "://" not in base_url:
        base_url = f"https://{base_url}"
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return base_url
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def _redact_preview(text: str, limit: int = EVIDENCE_PREVIEW_MAX_CHARS) -> str:
    preview = (text or "")[:max(int(limit or 0), 0)]
    for pattern, replacement in SECRET_REDACTIONS:
        preview = pattern.sub(replacement, preview)
    return preview


def _version_disclosure_request(url: str, timeout: int | float) -> tuple[int, str]:
    ctx = _build_ssl_context()
    req = urllib.request.Request(
        url,
        headers={"User-Agent": HTTP_USER_AGENT, "Accept": HTTP_ACCEPT},
        method="GET",
    )
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=timeout) as resp:
            return int(getattr(resp, "status", 0) or 0), resp.read(EVIDENCE_PREVIEW_MAX_CHARS * 4).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(EVIDENCE_PREVIEW_MAX_CHARS * 4).decode("utf-8", errors="ignore")
        except Exception:
            pass
        return int(getattr(exc, "code", 0) or 0), body
    except Exception:
        return 0, ""


def _classify_version_path(path: str, status: int, body: str) -> tuple[bool, bool, str, str, str]:
    if status in (401, 403):
        return True, True, "info", _framework_hint(path, body), "protected existence evidence"
    if status == 404 or status == 0:
        return False, False, "info", "", "absent"
    if status < 200 or status >= 400:
        return False, False, "info", "", f"http_{status}"

    lower = body.lower()
    sensitive = any(marker in lower for marker in SENSITIVE_BODY_MARKERS)
    hint = _framework_hint(path, body)
    if path == "/actuator/env":
        return True, False, "critical" if sensitive else "high", hint or "Spring Boot Actuator", "Spring Actuator environment exposure"
    if path in ("/actuator/mappings", "/actuator/beans"):
        return True, False, "high", hint or "Spring Boot Actuator", "Spring Actuator internals exposed"
    if path in ("/server-status", "/server-info"):
        detailed = any(marker in lower for marker in ("server uptime", "apache", "module", "requests/sec", "server version"))
        return True, False, "high" if detailed else "medium", hint or "Apache status", "server status/info exposure"
    if path == "/phpinfo.php":
        detailed = any(marker in lower for marker in ("php version", "phpinfo()", "loaded configuration file", "_server"))
        return True, False, "high" if detailed else "medium", hint or "PHP", "phpinfo exposure"
    if path in ("/telescope", "/horizon"):
        detailed = any(marker in lower for marker in ("laravel", "telescope", "horizon", "jobs", "redis"))
        return True, False, "high" if detailed else "medium", hint or "Laravel", "Laravel operational UI exposed"
    if path in ("/admin", "/wp-admin/"):
        return True, False, "medium", hint or ("WordPress" if path == "/wp-admin/" else "Admin interface"), "admin interface reachable"
    if path == "/wp-json/":
        return True, False, "medium", hint or "WordPress", "WordPress REST API exposed"
    if path in ("/CHANGELOG.md", "/readme.txt", "/readme.html", "/version.txt", "/build-info"):
        versioned = bool(re.search(r"\b(?:version|v)?\d+\.\d+(?:\.\d+)?\b", body, re.IGNORECASE))
        return True, False, "medium" if versioned else "low", hint, "public version/build disclosure"
    if path == "/.well-known/security.txt":
        return True, False, "info", hint, "security.txt present"
    return True, False, "low", hint, "reachable framework path"


def _framework_hint(path: str, body: str) -> str:
    lower = (body or "").lower()
    if "spring" in lower or path.startswith("/actuator/"):
        return "Spring Boot"
    if "laravel" in lower or path in ("/telescope", "/horizon"):
        return "Laravel"
    if "django" in lower:
        return "Django"
    if "wordpress" in lower or path.startswith("/wp-"):
        return "WordPress"
    if "phpinfo" in lower or "php version" in lower:
        return "PHP"
    if "apache" in lower or path.startswith("/server-"):
        return "Apache"
    return ""


def probe_version_disclosure(base_url: str, scope: ScopeValidator) -> dict:
    scope.assert_in_scope(base_url)
    normalized_base = _normalize_base_url(base_url)
    result = {"base_url": normalized_base, "paths": [], "findings": [], "coverage": {}}
    exposed = protected = absent = failed = 0

    for path in VERSION_DISCLOSURE_PATHS:
        url = urllib.parse.urljoin(normalized_base + "/", path.lstrip("/"))
        status, body = _version_disclosure_request(url, VERSION_DISCLOSURE_TIMEOUT)
        exists, is_protected, risk, hint, reason = _classify_version_path(path, status, body)
        preview = _redact_preview(body)
        entry = {
            "url": url,
            "path": path,
            "status_code": status,
            "exists": exists,
            "protected": is_protected,
            "risk": risk,
            "framework_hint": hint,
            "reason": reason,
            "evidence_preview": preview,
        }
        result["paths"].append(entry)
        if is_protected:
            protected += 1
        elif exists:
            exposed += 1
        elif status == 0:
            failed += 1
        else:
            absent += 1
        if exists and not is_protected and risk in {"low", "medium", "high", "critical"}:
            result["findings"].append({
                "title": f"{path} exposure",
                "path": path,
                "url": url,
                "severity": risk.upper(),
                "risk": risk,
                "framework_hint": hint,
                "description": reason,
                "evidence_preview": preview,
                "evidence_refs": ["probe_version_disclosure"],
            })

    result["coverage"] = {
        "paths_total": len(VERSION_DISCLOSURE_PATHS),
        "exposed": exposed,
        "protected": protected,
        "absent": absent,
        "failed": failed,
    }
    return result


def _target_timeout_profile(target: str) -> dict:
    if _is_slow_target(target):
        return {
            "probe_get": max(HTTP_PROBE_TIMEOUT_S, 16.0),
            "probe_head": max(HTTP_PROBE_HEAD_TIMEOUT_S, 6.0),
            "probe_curl": max(HTTP_PROBE_CURL_TIMEOUT_S, 18.0),
            "total_budget": max(HTTP_PROBE_TOTAL_BUDGET_S, 40.0),
            "misconfig_request": max(MISCONFIG_REQUEST_TIMEOUT_S, 3.5),
            "misconfig_budget": max(MISCONFIG_TOTAL_BUDGET_S, 35.0),
        }
    return {
        "probe_get": HTTP_PROBE_TIMEOUT_S,
        "probe_head": HTTP_PROBE_HEAD_TIMEOUT_S,
        "probe_curl": HTTP_PROBE_CURL_TIMEOUT_S,
        "total_budget": HTTP_PROBE_TOTAL_BUDGET_S,
        "misconfig_request": MISCONFIG_REQUEST_TIMEOUT_S,
        "misconfig_budget": MISCONFIG_TOTAL_BUDGET_S,
    }


def dns_lookup(domain: str, scope: ScopeValidator) -> dict:
    scope.assert_in_scope(domain)
    results = {"domain": domain, "records": {}}
    for rtype in ["A", "MX", "NS", "TXT", "CNAME"]:
        try:
            r = subprocess.run(["dig", "+short", rtype, domain],
                               capture_output=True, text=True, timeout=10)
            records = [x.strip() for x in r.stdout.strip().split("\n") if x.strip()]
            if records:
                results["records"][rtype] = records
        except Exception as e:
            results["records"][rtype] = f"Error: {e}"
    try:
        results["resolved_ip"] = socket.gethostbyname(domain)
    except Exception:
        pass
    return results


def whois_lookup(domain: str, scope: ScopeValidator) -> dict:
    scope.assert_in_scope(domain)
    try:
        r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
        fields = {}
        for line in r.stdout.split("\n"):
            for key in [
                "Registrar:",
                "Sponsoring Registrar:",
                "Creation Date:",
                "Updated Date:",
                "Expiry Date:",
                "Name Server:",
                "Registrant Organization:",
                "Registrant Org:",
                "Registrant Country:",
                "OrgName:",
                "Organization:",
                "Admin Email:",
                "Tech Email:",
                "Registrant Email:",
                "Registrar Abuse Contact Email:",
                "Abuse Email:",
            ]:
                if line.strip().startswith(key):
                    fields[key.rstrip(":")] = line.split(":", 1)[1].strip()
        return {"domain": domain, "fields": fields, "org_osint": _parse_whois_org_osint(r.stdout, fields)}
    except Exception as e:
        return {"domain": domain, "error": str(e)}


def port_scan(target: str, ports: str, scope: ScopeValidator) -> dict:
    scope.assert_in_scope(target)
    try:
        r = subprocess.run(
            ["nmap", "-sV", "--open", "-p", ports, "--script=banner", "-oX", "-", target],
            capture_output=True, text=True, timeout=120
        )
        open_ports = []
        service_inventory = parse_service_banners(r.stdout)
        try:
            root = ET.fromstring(r.stdout)
            for port in root.findall(".//port"):
                protocol = port.get("protocol", "")
                portid = port.get("portid", "")
                state = (port.find("state").get("state", "") if port.find("state") is not None else "")
                if state != "open":
                    continue
                service = port.find("service")
                service_parts = []
                if service is not None:
                    name = service.get("name", "").strip()
                    product = service.get("product", "").strip()
                    version = service.get("version", "").strip()
                    extrainfo = service.get("extrainfo", "").strip()
                    if name:
                        service_parts.append(name)
                    if product:
                        service_parts.append(f"{product}/{version}" if version else product)
                    elif version:
                        service_parts.append(version)
                    if extrainfo:
                        service_parts.append(extrainfo)
                line = f"{portid}/{protocol} open"
                if service_parts:
                    line += " " + " ".join(service_parts)
                open_ports.append(line)
        except ET.ParseError:
            open_ports = [l.strip() for l in r.stdout.split("\n") if "/tcp" in l and "open" in l]
        tech_from_nmap = []
        for line in open_ports:
            tech_from_nmap.extend(_extract_tech(line))
        return {"target": target, "open_ports": open_ports,
                "detected_tech": tech_from_nmap,
                "service_inventory": service_inventory,
                "raw_output": r.stdout[:3000]}
    except FileNotFoundError:
        return {"target": target, "error": "nmap not installed — brew install nmap"}
    except Exception as e:
        return {"target": target, "error": str(e)}


def _do_request(url: str, timeout: int | float = 10, method: str = "GET"):
    """Make one HTTP request, returns (headers_dict, body_str, status_int)."""
    ctx = _build_ssl_context()
    req = urllib.request.Request(url, headers={
        "User-Agent": HTTP_USER_AGENT,
        "Accept": HTTP_ACCEPT,
        "Range": f"bytes=0-{HTTP_PROBE_MAX_BODY_BYTES - 1}" if method == "GET" else "bytes=0-0",
    }, method=method)
    try:
        with urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx)).open(req, timeout=timeout) as resp:
            body = ""
            if method != "HEAD":
                body = resp.read(HTTP_PROBE_MAX_BODY_BYTES).decode("utf-8", errors="ignore")
            return dict(resp.headers), body, resp.status
    except urllib.error.HTTPError as exc:
        body = ""
        if method != "HEAD":
            try:
                body = exc.read(HTTP_PROBE_MAX_BODY_BYTES).decode("utf-8", errors="ignore")
            except Exception:
                body = ""
        return dict(exc.headers or {}), body, exc.code


def _curl_headers(url: str, timeout: int | float) -> tuple[dict, int, str]:
    timeout_s = max(float(timeout), 1.0)
    cmd = [
        "curl", "-k", "-sS", "-L", "-I",
        "--http1.1",
        "--max-time", str(timeout_s),
        "--connect-timeout", str(min(timeout_s, 3.0)),
        "-A", HTTP_USER_AGENT,
        "-H", f"Accept: {HTTP_ACCEPT}",
        "-w", "\nARES_HTTP_STATUS:%{http_code}\nARES_EFFECTIVE_URL:%{url_effective}",
        url,
    ]
    proc = subprocess.run(cmd, capture_output=True, timeout=max(int(timeout_s) + 2, 5))
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or b"curl failed").decode("utf-8", errors="ignore").strip())
    payload = proc.stdout.decode("utf-8", errors="ignore")
    m = re.search(r"\nARES_HTTP_STATUS:(\d{3})\nARES_EFFECTIVE_URL:(.*)$", payload, re.DOTALL)
    if not m:
        raise RuntimeError("curl headers parse failure")
    status = int(m.group(1))
    effective_url = m.group(2).strip() or url
    header_text = payload[:m.start()]
    header_blocks = [block.strip() for block in re.split(r"\r?\n\r?\n", header_text) if block.strip()]
    headers = {}
    if header_blocks:
        for line in header_blocks[-1].splitlines():
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()
    return headers, status, effective_url


def _curl_body(url: str, timeout: int | float) -> tuple[str, int, str]:
    timeout_s = max(float(timeout), 1.0)
    cmd = [
        "curl", "-k", "-sS", "-L",
        "--http1.1",
        "--max-time", str(timeout_s),
        "--connect-timeout", str(min(timeout_s, 3.0)),
        "-A", HTTP_USER_AGENT,
        "-H", f"Accept: {HTTP_ACCEPT}",
        "--range", f"0-{HTTP_PROBE_MAX_BODY_BYTES - 1}",
        "-w", "\nARES_HTTP_STATUS:%{http_code}\nARES_EFFECTIVE_URL:%{url_effective}",
        url,
    ]
    proc = subprocess.run(cmd, capture_output=True, timeout=max(int(timeout_s) + 2, 5))
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or b"curl failed").decode("utf-8", errors="ignore").strip())
    payload = proc.stdout.decode("utf-8", errors="ignore")
    m = re.search(r"\nARES_HTTP_STATUS:(\d{3})\nARES_EFFECTIVE_URL:(.*)$", payload, re.DOTALL)
    if not m:
        raise RuntimeError("curl body parse failure")
    status = int(m.group(1))
    effective_url = m.group(2).strip() or url
    return payload[:m.start()], status, effective_url


def http_probe(url: str, scope: ScopeValidator) -> dict:
    """
    Probe HTTP/HTTPS. Tries https first, falls back to http.
    Extracts versioned tech from headers, cookies, and HTML body.
    Returns cpe_strings ready for NVD CVE lookup.
    """
    scope.assert_in_scope(url)
    timeouts = _target_timeout_profile(url)
    started_at = time.monotonic()

    candidate_urls = _build_probe_candidates(url)
    headers, body, status = {}, "", 0
    probe_errors = []
    partial = False
    used_url = url
    used_method = ""
    used_transport = ""
    for try_url in candidate_urls:
        skip_remaining_urllib = False
        if time.monotonic() - started_at >= timeouts["total_budget"]:
            probe_errors.append(
                f"http_probe total budget exceeded after {round(time.monotonic() - started_at, 2)}s"
            )
            break
        for transport, method, timeout in (
            ("urllib", "GET", timeouts["probe_get"]),
            ("urllib", "HEAD", timeouts["probe_head"]),
            ("curl", "GET", timeouts["probe_curl"]),
            ("curl", "HEAD", timeouts["probe_head"]),
        ):
            if transport == "urllib" and skip_remaining_urllib:
                continue
            if time.monotonic() - started_at >= timeouts["total_budget"]:
                probe_errors.append(
                    f"http_probe total budget exceeded after {round(time.monotonic() - started_at, 2)}s"
                )
                break
            try:
                if transport == "urllib":
                    headers, body, status = _do_request(try_url, timeout=timeout, method=method)
                elif method == "GET":
                    headers, status, effective_url = _curl_headers(try_url, timeout=timeout)
                    body, body_status, effective_body_url = _curl_body(try_url, timeout=timeout)
                    status = status or body_status
                    used_url = effective_body_url or effective_url or try_url
                else:
                    headers, status, effective_url = _curl_headers(try_url, timeout=timeout)
                    body = ""
                    used_url = effective_url or try_url

                if transport == "urllib":
                    used_url = try_url
                used_method = method
                used_transport = transport
                if status or headers or body:
                    break
            except Exception as e:
                probe_errors.append(f"{try_url} [{transport} {method}]: {e}")
                if transport == "urllib" and _is_tls_handshake_error(e):
                    skip_remaining_urllib = True
        if status or headers or body:
            break

    probe_error = probe_errors[-1] if probe_errors else ""
    transport_recovered = bool(
        status and headers and body and used_method == "GET"
        and _normalize_probe_url(used_url) == _normalize_probe_url(candidate_urls[0])
    )
    partial = (
        used_method != "GET"
        or not body
        or _normalize_probe_url(used_url) != _normalize_probe_url(candidate_urls[0])
        or (bool(probe_errors) and not transport_recovered)
    )
    if transport_recovered:
        probe_error = ""

    if not headers and not body:
        return {"url": url, "error": probe_error, "tech_signals": [], "tech_details": [],
                "cpe_strings": [], "missing_security_headers": [], "security_headers": {}, "candidate_urls": candidate_urls}

    try:
        all_tech = []
        seen = set()

        def add_tech(tech_list):
            for t in tech_list:
                key = t["name"].split(" ")[0].lower()
                if key not in seen:
                    seen.add(key)
                    all_tech.append(t)

        server  = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")
        cookies = headers.get("Set-Cookie", "")

        if server:  add_tech(_extract_tech(server))
        if powered: add_tech(_extract_tech(powered))

        if "PHPSESSID" in cookies and "php" not in seen:
            all_tech.append({"name": "PHP (session cookie)", "version": "", "cpe": "php:php"})
            seen.add("php")
        if "JSESSIONID" in cookies and "tomcat" not in seen:
            all_tech.append({"name": "Java/Tomcat (session cookie)", "version": "", "cpe": "apache:tomcat"})
            seen.add("tomcat")

        add_tech(_extract_tech(body))

        sec = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "Content-Security-Policy":   headers.get("Content-Security-Policy"),
            "X-Frame-Options":           headers.get("X-Frame-Options"),
            "X-Content-Type-Options":    headers.get("X-Content-Type-Options"),
            "Referrer-Policy":           headers.get("Referrer-Policy"),
            "Permissions-Policy":        headers.get("Permissions-Policy"),
        }
        missing_security_headers = [k for k, v in sec.items() if not v]
        if used_url.startswith("http://") and "Strict-Transport-Security" in missing_security_headers:
            missing_security_headers.remove("Strict-Transport-Security")

        return {
            "url": used_url,
            "status_code": status,
            "partial": partial,
            "error": probe_error if probe_error else "",
            "candidate_urls": candidate_urls,
            "probe_method": used_method,
            "probe_transport": used_transport,
            "timeout_profile": timeouts,
            "server_header": server,
            "powered_by_header": powered,
            "tech_signals": [t["name"] for t in all_tech],
            "tech_details": all_tech,
            "cpe_strings": _cpe_strings(all_tech),
            "security_headers": sec,
            "missing_security_headers": missing_security_headers,
            "body_preview": body[:800]
        }
    except Exception as e:
        return {"url": used_url, "error": str(e), "tech_signals": [], "tech_details": [],
                "cpe_strings": [], "missing_security_headers": [], "security_headers": {}, "candidate_urls": candidate_urls}


def subdomain_enumerate(domain: str, wordlist: list, scope: ScopeValidator) -> dict:
    scope.assert_in_scope(domain)
    found = []
    for word in wordlist:
        sub = f"{word}.{domain}"
        try:
            ip = socket.gethostbyname(sub)
            found.append({"subdomain": sub, "ip": ip})
        except socket.gaierror:
            pass
    return {"domain": domain, "discovered_subdomains": found, "tested": len(wordlist)}


def fetch_cve_data(cpe_string: str) -> dict:
    from tools.cve_sources import fetch_cve_data as _fetch_cve_data

    return _fetch_cve_data(cpe_string)


def check_common_misconfigs(url: str, scope: ScopeValidator) -> dict:
    scope.assert_in_scope(url)
    base = url.rstrip("/")
    timeouts = _target_timeout_profile(url)

    paths = [
        ("/.env",                    "HIGH"),
        ("/.env.local",              "HIGH"),
        ("/.env.production",         "HIGH"),
        ("/.git/config",             "HIGH"),
        ("/.git/HEAD",               "HIGH"),
        ("/config.php",              "HIGH"),
        ("/wp-config.php",           "HIGH"),
        ("/web.config",              "HIGH"),
        ("/database.yml",            "HIGH"),
        ("/admin",                   "MEDIUM"),
        ("/admin/login",             "MEDIUM"),
        ("/wp-admin",                "MEDIUM"),
        ("/phpmyadmin",              "HIGH"),
        ("/pma",                     "HIGH"),
        ("/adminer.php",             "HIGH"),
        ("/api/v1",                  "LOW"),
        ("/swagger.json",            "MEDIUM"),
        ("/swagger-ui.html",         "MEDIUM"),
        ("/openapi.json",            "MEDIUM"),
        ("/graphql",                 "MEDIUM"),
        ("/robots.txt",              "INFO"),
        ("/sitemap.xml",             "INFO"),
        ("/server-status",           "HIGH"),
        ("/server-info",             "HIGH"),
        ("/.htaccess",               "MEDIUM"),
        ("/.well-known/security.txt","INFO"),
        ("/info.php",                "HIGH"),
        ("/phpinfo.php",             "HIGH"),
        ("/test.php",                "MEDIUM"),
        ("/debug.php",               "HIGH"),
        ("/backup.zip",              "HIGH"),
        ("/backup.sql",              "HIGH"),
        ("/dump.sql",                "HIGH"),
    ]

    findings = []
    restricted_findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    started_at = time.monotonic()
    paths_checked = 0
    budget_exhausted = False

    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    prioritized_paths = sorted(paths, key=lambda item: (severity_rank.get(item[1], 9), len(item[0])))

    def _probe_path(path: str):
        req = urllib.request.Request(
            base + path,
            headers={"User-Agent": "Mozilla/5.0 (ARES Security Research Platform)"},
            method="HEAD",
        )
        try:
            with _urlopen_no_redirect(req, timeout=min(timeouts["misconfig_request"], 1.0), ctx=ctx) as resp:
                return {"status": resp.status}
        except urllib.error.HTTPError as e:
            if e.code == 405:
                req = urllib.request.Request(
                    base + path,
                    headers={"User-Agent": "Mozilla/5.0 (ARES Security Research Platform)"},
                    method="GET",
                )
                try:
                    with _urlopen_no_redirect(req, timeout=timeouts["misconfig_request"], ctx=ctx) as resp:
                        return {"status": resp.status}
                except urllib.error.HTTPError as inner:
                    return {"status": inner.code}
            return {"status": e.code}
        except Exception as e:
            return {"error": str(e)}

    for path, severity in prioritized_paths:
        if time.monotonic() - started_at >= timeouts["misconfig_budget"]:
            budget_exhausted = True
            break
        paths_checked += 1
        result = _probe_path(path)
        status = result.get("status")
        if status == 200:
            findings.append({"path": path, "status": 200, "severity": severity})
        elif status in [401, 403]:
            restricted_findings.append({"path": path, "status": status, "severity": severity})
        elif status and status not in [404, 410]:
            findings.append({"path": path, "status": status, "severity": "INFO"})

    return {
        "target": url,
        "paths_checked": paths_checked,
        "paths_total": len(paths),
        "budget_exhausted": budget_exhausted,
        "elapsed_s": round(time.monotonic() - started_at, 2),
        "timeout_profile": timeouts,
        "findings": findings,
        "restricted_findings": restricted_findings,
        "high_severity_count": sum(1 for f in findings if f["severity"] == "HIGH")
    }
