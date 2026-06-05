# Requires Python 3.12+
"""
ARES FastAPI Server
Real-time streaming backend for the ARES dashboard.
Streams agent events via Server-Sent Events (SSE).

Usage:
    pip install fastapi "uvicorn[standard]" sse-starlette pydantic
    uvicorn server:app --reload --host 0.0.0.0 --port 8001
"""

import asyncio
import ipaddress
import json
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, AsyncGenerator
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, SecretStr
from sse_starlette.sse import EventSourceResponse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.scope_validator import Scope, ScopeValidator
from utils.capability_profiles import resolve_profile
from pipeline import ARESPipeline
from ollama_compat import check_ollama
from utils.auth import APIKeyMiddleware
from utils.rate_limit import check_and_record_new_session
from utils.config import (
    ALLOWED_ORIGINS,
    API_KEY,
    ENV,
    EVENT_QUEUE_SIZE,
    ENABLE_MANUAL_SECRET_VERIFY,
    OLLAMA_MODEL,
    PROFILE,
    SECRET_VERIFY_REQUIRE_ADVANCED_PROFILE,
    PRUNE_INTERVAL,
    SESSION_TTL,
    as_dict as config_dict,
)
from tools.secret_workbench import verify_operator_secret
from utils.session_store import (
    create_session,
    get_session,
    init_db,
    list_recent_sessions,
    prune_old_sessions as prune_old_session_records,
    update_session,
)

SESSION_TTL_SECONDS = SESSION_TTL
SESSION_PRUNE_INTERVAL_SECONDS = PRUNE_INTERVAL
_QUEUE_SIZE = EVENT_QUEUE_SIZE
_allowed_origins = ALLOWED_ORIGINS
VALID_MODES = {"full", "osint_only", "passive_only", "light_active", "recon_only"}

# ── Session store ─────────────────────────────────────────────────────────────
event_queues: dict[str, asyncio.Queue] = {}
_pipeline_tasks: dict[str, asyncio.Task] = {}
_prune_task: asyncio.Task | None = None


def _active_sessions() -> dict[str, dict]:
    return {s["id"]: s for s in list_recent_sessions(limit=1000)}


def _prune_old_sessions_once(ttl_seconds: int = SESSION_TTL_SECONDS):
    for session_id in prune_old_session_records(ttl_seconds):
        event_queues.pop(session_id, None)


async def _prune_old_sessions(ttl_seconds: int = SESSION_TTL_SECONDS):
    while True:
        await asyncio.sleep(SESSION_PRUNE_INTERVAL_SECONDS)
        _prune_old_sessions_once(ttl_seconds=ttl_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _prune_task
    init_db()
    _prune_task = asyncio.create_task(_prune_old_sessions())
    try:
        yield
    finally:
        if _prune_task:
            _prune_task.cancel()
            try:
                await _prune_task
            except asyncio.CancelledError:
                pass
            _prune_task = None

        running = list(_pipeline_tasks.values())
        for task in running:
            task.cancel()
        if running:
            await asyncio.gather(*running, return_exceptions=True)


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="ARES API",
    description="Autonomous Recon & Exploitation System",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-ARES-Key"],
)

_api_key = API_KEY
_env = ENV

if not _api_key:
    if _env != "dev":
        raise RuntimeError(
            "ARES_API_KEY environment variable is not set. "
            "Set it in .env or export it before starting the server. "
            "To run without auth during local dev only, set ARES_ENV=dev "
            "and ARES_API_KEY=dev-insecure."
        )
    _api_key = "dev-insecure"

app.add_middleware(APIKeyMiddleware, api_key=_api_key)
init_db()

# ── Cached Ollama status ──────────────────────────────────────────────────────
# /health returns instantly from cache — never blocks during inference
import time as _time
import threading as _threading

_ollama_cache = {"status": {"running": True, "models": []}, "ts": 0}


def _refresh_ollama_cache():
    """Refresh in background thread — never blocks health check."""
    try:
        _ollama_cache["status"] = check_ollama()
        _ollama_cache["ts"] = _time.time()
    except Exception:
        pass


def get_ollama_status() -> dict:
    now = _time.time()
    if now - _ollama_cache["ts"] > 30:
        _ollama_cache["ts"] = now  # prevent concurrent refreshes
        _threading.Thread(target=_refresh_ollama_cache, daemon=True).start()
    return _ollama_cache["status"]


# ── Models ────────────────────────────────────────────────────────────────────
class AssessmentRequest(BaseModel):
    target: str
    domains: Annotated[list[str], Field(default_factory=list, max_length=50)]
    ip_ranges: Annotated[list[str], Field(default_factory=list, max_length=20)]
    mode: str = "full"  # full | osint_only | recon_only
    profile: str | None = None
    roe_policy_path: str | None = Field(default=None, max_length=1024)


class AssessmentSession(BaseModel):
    session_id: str
    status: str
    target: str
    created_at: str


class ManualSecretVerifyRequest(BaseModel):
    type: str = "API Key"
    provider: str = "generic"
    profile: str = "advanced"
    secret_value: Annotated[SecretStr, Field(min_length=1, max_length=4096)]
    perform_metadata_check: bool = False
    secret_access_key: SecretStr | None = None
    session_token: SecretStr | None = None


# ── Helpers ───────────────────────────────────────────────────────────────────
def normalize_target(value: str) -> str:
    raw = value.strip()
    if not raw:
        return ""
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw
    return host.strip().lower().rstrip(".")


def format_sse_event(event_type: str, data: dict) -> dict:
    return {"event": event_type, "data": json.dumps(data)}


def _redacted_secret_preview(value: str) -> str:
    value = str(value or "")
    if len(value) <= 8:
        return value[:2] + "..." if value else ""
    return value[:4] + "..." + value[-4:]


def push_event(session_id: str, event_type: str, data: dict):
    queue = event_queues.get(session_id)
    if queue is None:
        return

    def _event(kind: str, payload: dict) -> dict:
        return {
            "type": kind,
            "data": payload,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    try:
        queue.put_nowait(_event(event_type, data))
    except asyncio.QueueFull:
        try:
            queue.get_nowait()
            queue.put_nowait(_event("warn", {"msg": "event queue overflow - oldest event dropped"}))
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(_event(event_type, data))
        except (asyncio.QueueFull, asyncio.QueueEmpty):
            pass


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/")
async def root(request: Request):
    if "text/html" in request.headers.get("accept", "") and os.path.exists("ARES_dashboard.html"):
        return FileResponse("ARES_dashboard.html", media_type="text/html")
    return {
        "service": "ARES",
        "version": "1.0.0",
        "status": "online",
        "endpoints": {
            "start":   "POST /assess",
            "status":  "GET  /assess/{session_id}/status",
            "stream":  "GET  /assess/{session_id}/stream",
            "results": "GET  /assess/{session_id}/results",
            "report":  "GET  /assess/{session_id}/report",
            "stop":    "POST /assess/{session_id}/stop"
        }
    }


@app.get("/ARES_dashboard.html")
async def dashboard():
    if not os.path.exists("ARES_dashboard.html"):
        raise HTTPException(404, "Dashboard not found")
    return FileResponse("ARES_dashboard.html", media_type="text/html")


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "config": config_dict(),
        "configured_model": OLLAMA_MODEL,
        "ollama": get_ollama_status(),
        "active_sessions": sum(
            1 for session in list_recent_sessions(limit=1000)
            if session.get("status") == "running"
        )
    }


@app.post("/assess", response_model=AssessmentSession)
async def start_assessment(req: AssessmentRequest):
    await check_and_record_new_session(_active_sessions())

    ollama_status = get_ollama_status()
    if not ollama_status["running"]:
        raise HTTPException(400, "Ollama is not running. Start with: ollama serve")

    target = normalize_target(req.target)
    domains = [normalize_target(domain) for domain in req.domains if normalize_target(domain)]
    ip_ranges = [ip_range.strip() for ip_range in req.ip_ranges if ip_range.strip()]
    mode = req.mode.strip().lower()
    try:
        profile = resolve_profile(req.profile or PROFILE, legacy_mode=mode).value
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    roe_policy_path = (req.roe_policy_path or "").strip()

    if not target:
        raise HTTPException(400, "Target is required")
    if mode not in VALID_MODES:
        raise HTTPException(400, f"Invalid mode. Expected one of: {', '.join(sorted(VALID_MODES))}")

    try:
        ipaddress.ip_address(target)
        if not ip_ranges:
            ip_ranges = [f"{target}/32"]
    except ValueError:
        pass

    scope_domains = domains if domains else [target, f"*.{target}"]
    scope = Scope(domains=scope_domains, ip_ranges=ip_ranges)

    validator = ScopeValidator(scope)
    valid, reason = validator.validate(target)
    if not valid:
        raise HTTPException(400, f"Target out of scope: {reason}")

    session_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    create_session(session_id, target, mode, created_at)
    event_queues[session_id] = asyncio.Queue(maxsize=_QUEUE_SIZE)

    task = asyncio.create_task(
        run_pipeline_background(
            session_id=session_id,
            target=target,
            scope=scope,
            mode=mode,
            profile=profile,
            roe_policy_path=roe_policy_path,
        )
    )
    _pipeline_tasks[session_id] = task

    def _on_done(t: asyncio.Task, sid=session_id):
        _pipeline_tasks.pop(sid, None)
        if t.cancelled():
            update_session(sid, status="stopped", completed_at=time.time())
        elif t.exception():
            update_session(sid, status="error", completed_at=time.time())

    task.add_done_callback(_on_done)

    return AssessmentSession(
        session_id=session_id,
        status="running",
        target=target,
        created_at=created_at,
    )


@app.get("/assess/{session_id}/stream")
async def stream_events(session_id: str):
    """SSE endpoint — streams real-time agent events to the dashboard."""
    session = get_session(session_id)
    if session is None:
        raise HTTPException(404, "Session not found")

    async def event_generator() -> AsyncGenerator:
        yield format_sse_event("connected", {
            "session_id": session_id,
            "target": session["target"]
        })

        queue = event_queues.get(session_id)
        if not queue:
            return

        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=15.0)
                yield format_sse_event(event["type"], event["data"])
                if event["type"] in ("complete", "error", "stopped"):
                    while not queue.empty():
                        try:
                            remaining = queue.get_nowait()
                            yield format_sse_event(remaining["type"], remaining["data"])
                        except asyncio.QueueEmpty:
                            break
                    break
            except asyncio.TimeoutError:
                # Keepalive ping — keeps SSE connection alive during long Ollama calls
                yield format_sse_event("ping", {"ts": datetime.now(timezone.utc).isoformat()})
            except Exception:
                break

    return EventSourceResponse(event_generator())


@app.get("/assess/{session_id}/results")
async def get_results(session_id: str):
    session = get_session(session_id)
    if session is None:
        raise HTTPException(404, "Session not found")
    return {
        "session_id": session_id,
        "target": session["target"],
        "status": session["status"],
        "results": session["results"]
    }


@app.get("/assess/{session_id}/status")
async def get_status(session_id: str):
    """Lightweight status poll - no SSE stream required."""
    session = get_session(session_id)
    if session is None:
        raise HTTPException(404, "Session not found")
    queue = event_queues.get(session_id)
    return {
        "session_id": session_id,
        "target": session["target"],
        "status": session["status"],
        "created_at": session["created_at"],
        "completed_at": session.get("completed_at"),
        "queue_depth": queue.qsize() if queue else 0,
        "report_ready": bool(session.get("report_path")),
    }


@app.get("/assess/{session_id}/report")
async def get_report(session_id: str):
    session = get_session(session_id)
    if session is None:
        raise HTTPException(404, "Session not found")
    report_path = session.get("report_path")
    if not report_path or not os.path.exists(report_path):
        raise HTTPException(404, "Report not yet generated")
    return FileResponse(
        report_path,
        media_type="text/markdown",
        filename=f"ARES_Report_{session['target']}_{session_id[:8]}.md"
    )


@app.post("/assess/{session_id}/stop")
async def stop_assessment(session_id: str):
    if get_session(session_id) is None:
        raise HTTPException(404, "Session not found")
    update_session(session_id, abort=True, status="stopped", completed_at=time.time())
    push_event(session_id, "stopped", {"message": "Assessment aborted by operator"})
    return {"status": "stopped", "session_id": session_id}


@app.post("/manual/verify-secret")
async def manual_verify_secret(req: ManualSecretVerifyRequest):
    if not ENABLE_MANUAL_SECRET_VERIFY:
        raise HTTPException(404, "Manual secret verification is disabled")
    profile = resolve_profile(req.profile)
    if SECRET_VERIFY_REQUIRE_ADVANCED_PROFILE and profile.value not in {"advanced", "custom"}:
        raise HTTPException(403, "Manual secret verification requires advanced or custom profile")
    try:
        result = verify_operator_secret(
            req.provider,
            req.secret_value.get_secret_value(),
            perform_metadata_check=req.perform_metadata_check,
            secret_access_key=req.secret_access_key.get_secret_value() if req.secret_access_key else "",
            session_token=req.session_token.get_secret_value() if req.session_token else "",
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {
        "type": req.type,
        "manual_only": True,
        "real_provider_calls": bool(req.perform_metadata_check),
        **result,
    }


@app.get("/assess")
async def list_sessions():
    recent = list_recent_sessions(limit=20)
    return [{"id": s["id"], "target": s["target"], "status": s["status"],
             "created_at": s["created_at"]} for s in recent]


# ── Background pipeline runner ────────────────────────────────────────────────
class SessionState(dict):
    def __init__(self, session_id: str):
        super().__init__(get_session(session_id) or {})
        self._session_id = session_id

    def _refresh(self):
        self.clear()
        self.update(get_session(self._session_id) or {})

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if key in {"status", "completed_at", "results", "report_path", "abort"}:
            update_session(self._session_id, **{key: value})

    def get(self, key, default=None):
        self._refresh()
        return super().get(key, default)


async def run_pipeline_background(
    session_id: str,
    target: str,
    scope: Scope,
    mode: str,
    profile: str | None = None,
    roe_policy_path: str = "",
):
    session = SessionState(session_id)

    def emit(event_type: str, data: dict):
        push_event(session_id, event_type, data)

    def log(tag: str, msg: str, color: str = ""):
        emit("log", {"tag": tag, "msg": msg, "color": color})

    def phase_update(phase: str, status: str, detail: str = ""):
        emit("phase", {"phase": phase, "status": status, "detail": detail})

    try:
        log("ORCH", f"ARES assessment initialized — target: {target}", "blue")
        log("ORCH", f"Mode: {mode.upper()} | Profile: {(profile or 'recon').upper()} | Scope domains: {len(scope.domains)}", "blue")

        pipeline = ARESPipeline(
            target=target,
            scope=scope,
            mode=mode,
            profile=profile,
            roe_policy_path=roe_policy_path,
            session=session,
            log_fn=log,
            phase_fn=phase_update,
            emit_fn=emit
        )

        results = await pipeline.run()

        update_session(session_id, results=results)
        if not session.get("abort"):
            update_session(
                session_id,
                status="complete",
                report_path=results.get("report_path"),
                completed_at=time.time(),
            )
            emit("complete", {
                "target": target,
                "risk": results.get("redteam", {}).get("overall_risk", "UNKNOWN"),
                "report_path": results.get("report_path", ""),
                "summary": results.get("osint", {}).get("summary", "")
            })
        else:
            update_session(session_id, completed_at=time.time())

    except Exception as e:
        update_session(session_id, status="error", completed_at=time.time())
        log("WARN", f"Pipeline error: {str(e)}", "red")
        emit("error", {"message": str(e)})
