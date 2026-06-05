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
        "event_queue_size": EVENT_QUEUE_SIZE,
    }
