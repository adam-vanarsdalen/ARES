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
import json
import logging
import os
from pathlib import Path
import sys
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, AsyncGenerator
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, SecretStr
from sse_starlette.sse import EventSourceResponse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.scope_validator import (
    Scope,
    ScopeValidator,
    normalize_target_url,
    scope_from_target_and_roe,
    validate_target_or_raise,
)
from utils.capability_profiles import resolve_profile
from utils.roe import evaluate_capability_action, load_roe_policy
from pipeline import ARESPipeline
from ollama_compat import check_ollama
from utils.auth import APIKeyMiddleware
from utils.rate_limit import reserve_new_session
from utils.config import (
    ALLOWED_ORIGINS,
    API_KEY,
    ENV,
    EVENT_QUEUE_SIZE,
    ENABLE_ADVANCED_VERIFICATION,
    ENABLE_MANUAL_SECRET_VERIFY,
    OLLAMA_MODEL,
    PROFILE,
    ROE_POLICY_ID,
    SECRET_VERIFY_REQUIRE_ADVANCED_PROFILE,
    PRUNE_INTERVAL,
    SESSION_TTL,
    as_dict as config_dict,
)
from tools.secret_workbench import verify_operator_secret
from tools.sbom_ingest import ingest_sbom
from utils.finding_lifecycle import find_finding, initialize_findings, review_finding
from exporters.stix_exporter import build_stix_bundle
from exporters.oscal_exporter import build_oscal_assessment_results
from exporters.openvex_exporter import build_openvex
from exporters.csaf_exporter import build_csaf_advisory
from utils.audit_log import append_audit_event
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
    allow_methods=["GET", "POST", "PATCH"],
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

if _env == "dev":
    logging.warning(
        "ARES is running in DEV mode with a well-known API key. "
        "Do NOT expose this server on a public network interface."
    )

app.add_middleware(APIKeyMiddleware, api_key=_api_key)
init_db()

# ── Cached Ollama status ──────────────────────────────────────────────────────
_ollama_cache = {"status": {"running": True, "models": []}, "ts": 0}


def _refresh_ollama_cache():
    """Refresh in background thread — never blocks health check."""
    try:
        _ollama_cache["status"] = check_ollama()
        _ollama_cache["ts"] = time.time()
    except Exception:
        pass


def get_ollama_status() -> dict:
    now = time.time()
    if now - _ollama_cache["ts"] > 30:
        _ollama_cache["ts"] = now  # prevent concurrent refreshes
        threading.Thread(target=_refresh_ollama_cache, daemon=True).start()
    return _ollama_cache["status"]


# ── Models ────────────────────────────────────────────────────────────────────
class AssessmentRequest(BaseModel):
    target: str
    domains: Annotated[list[str], Field(default_factory=list, max_length=50)]
    ip_ranges: Annotated[list[str], Field(default_factory=list, max_length=20)]
    mode: str = "full"  # full | osint_only | recon_only
    profile: str | None = None
    policy_id: str | None = Field(default=None, max_length=128)


class AssessmentSession(BaseModel):
    session_id: str
    status: str
    target: str
    created_at: str


class ManualSecretVerifyRequest(BaseModel):
    type: str = "API Key"
    provider: str = "generic"
    profile: str | None = None
    policy_id: str | None = Field(default=None, max_length=128)
    operator_confirmation: bool = False
    secret_value: Annotated[SecretStr, Field(min_length=1, max_length=4096)]
    perform_metadata_check: bool = False
    secret_access_key: SecretStr | None = None
    session_token: SecretStr | None = None


class FindingReviewRequest(BaseModel):
    lifecycle_state: str | None = None
    analyst_notes: str | None = Field(default=None, max_length=4000)
    duplicate_of: str | None = Field(default=None, max_length=256)
    false_positive_reason: str | None = Field(default=None, max_length=2000)
    accepted_risk_reason: str | None = Field(default=None, max_length=2000)
    next_best_manual_test: str | None = Field(default=None, max_length=2000)


# ── Helpers ───────────────────────────────────────────────────────────────────
def normalize_target(value: str) -> str:
    try:
        return (urlsplit(normalize_target_url(value)).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


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


_SBOM_MAX_BYTES = 10 * 1024 * 1024  # 10 MB


@app.post("/sbom/analyze")
async def analyze_sbom(request: Request):
    """Accept a CycloneDX JSON SBOM body and return correlated CVE findings."""
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > _SBOM_MAX_BYTES:
        return JSONResponse(status_code=413, content={"error": "sbom_too_large"})
    body = await request.body()
    if len(body) > _SBOM_MAX_BYTES:
        return JSONResponse(status_code=413, content={"error": "sbom_too_large"})
    try:
        sbom_data = json.loads(body)
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_sbom_json"})
    return JSONResponse(ingest_sbom(sbom_data))


@app.post("/assess", response_model=AssessmentSession)
async def start_assessment(req: AssessmentRequest):
    ollama_status = get_ollama_status()
    if not ollama_status["running"]:
        raise HTTPException(400, "Ollama is not running. Start with: ollama serve")

    if req.domains or req.ip_ranges:
        raise HTTPException(
            400,
            "Client-provided scope is not accepted. Select a server-managed RoE policy ID.",
        )
    try:
        target_url = normalize_target_url(req.target)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    target = urlsplit(target_url).hostname or ""
    mode = req.mode.strip().lower()
    try:
        profile = resolve_profile(req.profile or PROFILE, legacy_mode=mode).value
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    policy_id = (req.policy_id or ROE_POLICY_ID or "").strip()
    try:
        roe = load_roe_policy(policy_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    if not target:
        raise HTTPException(400, "Target is required")
    if mode not in VALID_MODES:
        raise HTTPException(400, f"Invalid mode. Expected one of: {', '.join(sorted(VALID_MODES))}")

    try:
        scope = scope_from_target_and_roe(target_url, roe)
        validate_target_or_raise(target_url, roe=roe, profile=profile, scope=scope)
    except ValueError as exc:
        raise HTTPException(400, f"Target blocked: {exc}") from exc

    async with reserve_new_session(_active_sessions):
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
                policy_id=policy_id,
            )
        )
        _pipeline_tasks[session_id] = task

    def _on_done(t: asyncio.Task, sid=session_id):
        _pipeline_tasks.pop(sid, None)
        if t.cancelled():
            update_session(sid, status="stopped", completed_at=time.time())
        elif t.exception() and (get_session(sid) or {}).get("status") == "running":
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
    results = {k: v for k, v in session["results"].items() if k != "report_path"}
    return {
        "session_id": session_id,
        "target": session["target"],
        "status": session["status"],
        "results": results
    }


@app.get("/assess/{session_id}/findings")
async def get_findings(session_id: str):
    session = get_session(session_id)
    if session is None:
        raise HTTPException(404, "Session not found")
    findings = initialize_findings(session["results"])
    return {
        "session_id": session_id,
        "findings": sorted(
            findings,
            key=lambda item: (-item.get("reportability_score", 0), item.get("title", "")),
        ),
    }


@app.patch("/assess/{session_id}/findings/{finding_id}/review")
async def patch_finding_review(session_id: str, finding_id: str, req: FindingReviewRequest):
    session = get_session(session_id)
    if session is None:
        raise HTTPException(404, "Session not found")
    finding = find_finding(session["results"], finding_id)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    updates = req.model_dump(exclude_none=True)
    try:
        reviewed = review_finding(finding, updates)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    redteam = session["results"].setdefault("redteam", {})
    manifest = redteam.get("run_manifest") or session["results"].get("recon", {}).get("run_manifest", {})
    audit_events = redteam.setdefault("audit_log", [])
    appended = append_audit_event(
        audit_events,
        manifest.get("run_id", session_id),
        "finding_state_changed",
        profile=(manifest.get("profile") or {}).get("profile", ""),
        action_summary=f"{finding_id} changed to {reviewed.get('lifecycle_state')}",
        finding_id=finding_id,
        decision={"analyst_review": True, "lifecycle_state": reviewed.get("lifecycle_state")},
    )
    manifest["audit_chain_head"] = appended["event_hash"]
    update_session(session_id, results=session["results"])
    return {"session_id": session_id, "finding": reviewed}


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
async def get_report(session_id: str, format: str = ""):
    session = get_session(session_id)
    if session is None:
        raise HTTPException(404, "Session not found")
    if format:
        builders = {
            "stix": build_stix_bundle,
            "oscal": build_oscal_assessment_results,
            "openvex": build_openvex,
            "csaf": build_csaf_advisory,
        }
        builder = builders.get(format.lower())
        if builder is None:
            raise HTTPException(400, "Unsupported report format")
        results = session.get("results") or {}
        if not results:
            raise HTTPException(404, "Assessment results not yet available")
        osint_report = results.get("osint", {})
        vuln_report = results.get("recon", {})
        redteam_report = results.get("redteam", {})
        manifest = (
            osint_report.get("run_manifest")
            or vuln_report.get("run_manifest")
            or redteam_report.get("run_manifest")
            or {}
        )
        return JSONResponse(builder(
            session["target"],
            osint_report,
            vuln_report,
            redteam_report,
            manifest,
        ))
    report_path = session.get("report_path")
    if not report_path or not os.path.exists(report_path):
        raise HTTPException(404, "Report not yet generated")
    _reports_dir = Path(__file__).resolve().parent / "reports"
    try:
        if not Path(report_path).resolve().is_relative_to(_reports_dir):
            raise HTTPException(403, "Invalid report path")
    except (TypeError, ValueError):
        raise HTTPException(403, "Invalid report path")
    return FileResponse(
        report_path,
        media_type="text/markdown",
        filename=f"ARES_Report_{session['target']}_{session_id[:8]}.md"
    )


@app.post("/assess/{session_id}/stop")
async def stop_assessment(session_id: str):
    session = get_session(session_id)
    if session is None:
        raise HTTPException(404, "Session not found")
    update_session(session_id, abort=True, status="stopped", completed_at=time.time())
    task = _pipeline_tasks.get(session_id)
    if task and not task.done():
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    push_event(session_id, "stopped", {
        "message": "Assessment cancelled by operator",
        "partial_evidence_preserved": True,
    })
    return {"status": "stopped", "session_id": session_id}


@app.post("/manual/verify-secret")
async def manual_verify_secret(req: ManualSecretVerifyRequest):
    if not ENABLE_MANUAL_SECRET_VERIFY:
        raise HTTPException(404, "Manual secret verification is disabled")
    if not ENABLE_ADVANCED_VERIFICATION:
        raise HTTPException(403, "Advanced verification is disabled by server configuration")
    effective_profile = resolve_profile(PROFILE)
    if SECRET_VERIFY_REQUIRE_ADVANCED_PROFILE and effective_profile.value not in {"advanced", "custom"}:
        raise HTTPException(403, "Server capability profile does not permit secret verification")
    if not req.operator_confirmation:
        raise HTTPException(403, "Explicit operator confirmation is required")
    policy_id = (req.policy_id or ROE_POLICY_ID or "").strip()
    try:
        roe = load_roe_policy(policy_id)
    except ValueError as exc:
        raise HTTPException(403, str(exc)) from exc
    decision = evaluate_capability_action(
        {"name": "secret_verification", "method": "GET"},
        effective_profile,
        roe,
        ScopeValidator(Scope(), roe=roe, profile=effective_profile.value),
    )
    if not decision["allowed"]:
        raise HTTPException(403, decision["reason"])
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
    policy_id: str = "",
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
            policy_id=policy_id,
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
                "report_ready": bool(results.get("report_path")),
                "summary": results.get("osint", {}).get("summary", "")
            })
        else:
            update_session(session_id, completed_at=time.time())

    except asyncio.CancelledError:
        update_session(session_id, status="stopped", completed_at=time.time())
        raise
    except Exception as e:
        update_session(session_id, status="error", completed_at=time.time())
        log("WARN", f"Pipeline error: {str(e)}", "red")
        emit("error", {"message": str(e)})
