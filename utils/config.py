"""
ARES configuration - single source of truth.

All env var reads go through this module. Import config values from here,
not from os.getenv scattered across the codebase.
"""

import os


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (ValueError, TypeError):
        return default


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (ValueError, TypeError):
        return default


def _str(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes"}


def _list(name: str, default: str = "") -> list[str]:
    raw = os.getenv(name, default)
    return [x.strip() for x in raw.split(",") if x.strip()]


API_KEY = _str("ARES_API_KEY")
ENV = _str("ARES_ENV", "prod")
ALLOWED_ORIGINS = _list(
    "ARES_ALLOWED_ORIGINS",
    "null,http://localhost:8001,http://127.0.0.1:8001,"
    "http://localhost:5173,http://localhost:3000,"
    "http://127.0.0.1:5173,http://127.0.0.1:3000",
)

OLLAMA_MODEL = _str("ARES_OLLAMA_MODEL", "qwen3.5:9b")
OLLAMA_BASE_URL = _str("ARES_OLLAMA_BASE_URL", _str("ARES_OLLAMA_BASE", "http://localhost:11434"))
OLLAMA_USE_NO_THINK_PROMPT = _bool("ARES_OLLAMA_USE_NO_THINK_PROMPT")
OLLAMA_TIMEOUT = _int("ARES_OLLAMA_TIMEOUT_S", 180)
OLLAMA_MAX_RETRIES = _int("ARES_OLLAMA_MAX_RETRIES", 2)

DB_PATH = _str("ARES_DB_PATH", "ares.db")
SESSION_TTL = _int("ARES_SESSION_TTL_SECONDS", 3600)
PRUNE_INTERVAL = _int("ARES_SESSION_PRUNE_INTERVAL_SECONDS", 600)
EVENT_QUEUE_SIZE = _int("ARES_EVENT_QUEUE_SIZE", 1000)

MAX_CONCURRENT = _int("ARES_MAX_CONCURRENT_SESSIONS", 5)
MAX_PER_MINUTE = _int("ARES_MAX_SESSIONS_PER_MINUTE", 10)

HTTP_PROBE_TIMEOUT = _float("ARES_HTTP_PROBE_TIMEOUT_S", 6.0)
HTTP_PROBE_HEAD_TIMEOUT = _float("ARES_HTTP_PROBE_HEAD_TIMEOUT_S", 3.0)
HTTP_PROBE_CURL_TIMEOUT = _float("ARES_HTTP_PROBE_CURL_TIMEOUT_S", 8.0)
HTTP_PROBE_TOTAL_BUDGET = _float("ARES_HTTP_PROBE_TOTAL_BUDGET_S", 15.0)
HTTP_PROBE_MAX_BODY_BYTES = _int("ARES_HTTP_PROBE_MAX_BODY_BYTES", 4096)

MISCONFIG_TIMEOUT = _float("ARES_MISCONFIG_TIMEOUT_S", 2.0)
MISCONFIG_TOTAL_BUDGET = _float("ARES_MISCONFIG_TOTAL_BUDGET_S", 20.0)

JS_INTEL_BUDGET = _float("ARES_JS_INTEL_BUDGET_S", 20.0)
EXTERNAL_LOOKUP_TIMEOUT = _float("ARES_EXTERNAL_LOOKUP_TIMEOUT_S", 8.0)
ENABLE_REVERSE_IP = _bool("ARES_ENABLE_REVERSE_IP", False)
PASSIVE_HTTP_ALLOWED = _bool("ARES_PASSIVE_HTTP_ALLOWED", False)
ENABLE_NMAP = _bool("ARES_ENABLE_NMAP", True)
REVERSE_IP_MAX_HOSTS = _int("ARES_REVERSE_IP_MAX_HOSTS", 50)
PASSIVE_URL_TIMEOUT = _float("ARES_PASSIVE_URL_TIMEOUT_S", 8.0)
SITEMAP_MAX_CHILDREN = _int("ARES_SITEMAP_MAX_CHILDREN", 5)
PASSIVE_URL_MAX = _int("ARES_PASSIVE_URL_MAX", 100)
SUBDOMAIN_WORDLIST_PATH = _str("ARES_SUBDOMAIN_WORDLIST_PATH", "wordlists/subdomains-500.txt")
SUBDOMAIN_WORDLIST_MAX = _int("ARES_SUBDOMAIN_WORDLIST_MAX", 500)
VERSION_DISCLOSURE_TIMEOUT = _float("ARES_VERSION_DISCLOSURE_TIMEOUT_S", 8.0)
EVIDENCE_PREVIEW_MAX_CHARS = _int("ARES_EVIDENCE_PREVIEW_MAX_CHARS", 500)
RECON_ADDITIONAL_TARGET_MAX = _int("ARES_RECON_ADDITIONAL_TARGET_MAX", 20)
ASSET_INVENTORY_MAX_HTTP_PROBES = _int("ARES_ASSET_INVENTORY_MAX_HTTP_PROBES", 20)
TLS_TIMEOUT = _float("ARES_TLS_TIMEOUT_S", 8.0)
TLS_ADDITIONAL_TARGET_MAX = _int("ARES_TLS_ADDITIONAL_TARGET_MAX", 5)
ENABLE_RISKY_METHOD_CHECKS = _bool("ARES_ENABLE_RISKY_METHOD_CHECKS", False)
API_ENUM_MAX_PATHS = _int("ARES_API_ENUM_MAX_PATHS", 12)
REDTEAM_MAX_VERIFICATIONS = _int("ARES_REDTEAM_MAX_VERIFICATIONS", 20)
ATTACK_GRAPH_MAX_ROUTE_NODES = _int("ARES_ATTACK_GRAPH_MAX_ROUTE_NODES", 50)
ATTACK_GRAPH_MAX_FORM_NODES = _int("ARES_ATTACK_GRAPH_MAX_FORM_NODES", 30)
ATTACK_GRAPH_MAX_API_NODES = _int("ARES_ATTACK_GRAPH_MAX_API_NODES", 50)
NVD_API_KEY = _str("ARES_NVD_API_KEY", "")
NVD_MIN_DELAY = _float("ARES_NVD_MIN_DELAY_S", 0.8 if NVD_API_KEY else 6.5)
CVE_CACHE_TTL = _int("ARES_CVE_CACHE_TTL_S", 86400)
ENABLE_VULNERS = _bool("ARES_ENABLE_VULNERS", False)
VULNERS_API_KEY = _str("ARES_VULNERS_API_KEY", "")
ENABLE_MANUAL_SECRET_VERIFY = _bool("ARES_ENABLE_MANUAL_SECRET_VERIFY", False)
PROFILE = _str("ARES_PROFILE", "recon").lower()
ENABLE_ADVANCED_VERIFICATION = _bool("ARES_ENABLE_ADVANCED_VERIFICATION", False)
REQUIRE_ROE_FOR_ADVANCED = _bool("ARES_REQUIRE_ROE_FOR_ADVANCED", True)
ENABLE_LAB_EXPLOIT_SIMULATION = _bool("ARES_ENABLE_LAB_EXPLOIT_SIMULATION", False)
REQUIRE_LOCAL_TARGET_FOR_LAB_EXPLOIT_SIM = _bool("ARES_REQUIRE_LOCAL_TARGET_FOR_LAB_EXPLOIT_SIM", True)
NUCLEI_PROFILE = _str("ARES_NUCLEI_PROFILE", "safe").lower()
ROE_POLICY_PATH = _str("ARES_ROE_POLICY_PATH", "")

SAFE_TARGETS = set(_list(
    "ARES_SAFE_TARGETS",
    "testphp.vulnweb.com,demo.testfire.net,zero.webappsecurity.com",
))


def as_dict() -> dict:
    """Return safe (non-secret) config for /health endpoint."""
    return {
        "env": ENV,
        "ollama_model": OLLAMA_MODEL,
        "session_ttl_s": SESSION_TTL,
        "max_concurrent": MAX_CONCURRENT,
        "max_per_minute": MAX_PER_MINUTE,
        "http_probe_budget": HTTP_PROBE_TOTAL_BUDGET,
        "external_lookup_timeout_s": EXTERNAL_LOOKUP_TIMEOUT,
        "enable_reverse_ip": ENABLE_REVERSE_IP,
        "passive_http_allowed": PASSIVE_HTTP_ALLOWED,
        "enable_nmap": ENABLE_NMAP,
        "reverse_ip_max_hosts": REVERSE_IP_MAX_HOSTS,
        "passive_url_timeout_s": PASSIVE_URL_TIMEOUT,
        "passive_url_max": PASSIVE_URL_MAX,
        "sitemap_max_children": SITEMAP_MAX_CHILDREN,
        "subdomain_wordlist_path": SUBDOMAIN_WORDLIST_PATH,
        "subdomain_wordlist_max": SUBDOMAIN_WORDLIST_MAX,
        "version_disclosure_timeout_s": VERSION_DISCLOSURE_TIMEOUT,
        "evidence_preview_max_chars": EVIDENCE_PREVIEW_MAX_CHARS,
        "recon_additional_target_max": RECON_ADDITIONAL_TARGET_MAX,
        "asset_inventory_max_http_probes": ASSET_INVENTORY_MAX_HTTP_PROBES,
        "tls_timeout_s": TLS_TIMEOUT,
        "tls_additional_target_max": TLS_ADDITIONAL_TARGET_MAX,
        "enable_risky_method_checks": ENABLE_RISKY_METHOD_CHECKS,
        "api_enum_max_paths": API_ENUM_MAX_PATHS,
        "redteam_max_verifications": REDTEAM_MAX_VERIFICATIONS,
        "attack_graph_max_route_nodes": ATTACK_GRAPH_MAX_ROUTE_NODES,
        "attack_graph_max_form_nodes": ATTACK_GRAPH_MAX_FORM_NODES,
        "attack_graph_max_api_nodes": ATTACK_GRAPH_MAX_API_NODES,
        "nvd_min_delay_s": NVD_MIN_DELAY,
        "cve_cache_ttl_s": CVE_CACHE_TTL,
        "enable_vulners": ENABLE_VULNERS,
        "enable_manual_secret_verify": ENABLE_MANUAL_SECRET_VERIFY,
        "profile": PROFILE,
        "enable_advanced_verification": ENABLE_ADVANCED_VERIFICATION,
        "require_roe_for_advanced": REQUIRE_ROE_FOR_ADVANCED,
        "enable_lab_exploit_simulation": ENABLE_LAB_EXPLOIT_SIMULATION,
        "require_local_target_for_lab_exploit_sim": REQUIRE_LOCAL_TARGET_FOR_LAB_EXPLOIT_SIM,
        "nuclei_profile": NUCLEI_PROFILE,
        "roe_policy_configured": bool(ROE_POLICY_PATH),
        "event_queue_size": EVENT_QUEUE_SIZE,
    }
