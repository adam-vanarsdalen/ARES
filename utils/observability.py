"""Optional OpenTelemetry integration with a dependency-free no-op fallback."""

from __future__ import annotations

from contextlib import contextmanager

from utils.config import ENABLE_OTEL, OTEL_EXPORTER_OTLP_ENDPOINT


def otel_status() -> dict:
    if not ENABLE_OTEL:
        return {"enabled": False, "available": False, "reason": "disabled"}
    try:
        import opentelemetry.trace  # noqa: F401
    except ImportError:
        return {"enabled": True, "available": False, "reason": "dependency_missing"}
    return {
        "enabled": True,
        "available": True,
        "endpoint_configured": bool(OTEL_EXPORTER_OTLP_ENDPOINT),
    }


@contextmanager
def trace_span(name: str, attributes: dict | None = None):
    status = otel_status()
    if not status["available"]:
        yield None
        return
    from opentelemetry import trace

    tracer = trace.get_tracer("ares")
    with tracer.start_as_current_span(name) as span:
        for key, value in (attributes or {}).items():
            span.set_attribute(key, value)
        yield span
