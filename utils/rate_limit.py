"""
Simple in-process rate limiter for ARES.

Provides:
  - Global concurrent session cap  (ARES_MAX_CONCURRENT_SESSIONS, default 5)
  - Per-minute new-session cap     (ARES_MAX_SESSIONS_PER_MINUTE, default 10)

NOTE: State is per-process and does not survive restarts. For multi-instance
deployments behind a load balancer, replace _recent_starts / _pending_sessions
with a shared store (e.g., Redis or a DB counter) to enforce limits correctly.
"""

import asyncio
import time
from contextlib import asynccontextmanager
from collections.abc import Callable

from fastapi import HTTPException
from utils.config import MAX_CONCURRENT, MAX_PER_MINUTE

_MAX_CONCURRENT = MAX_CONCURRENT
_MAX_PER_MINUTE = MAX_PER_MINUTE

_recent_starts: list[float] = []
_lock = asyncio.Lock()
_pending_sessions = 0


def _running_count(active_sessions: dict | Callable[[], dict]) -> int:
    sessions = active_sessions() if callable(active_sessions) else active_sessions
    return sum(
        1 for session in sessions.values()
        if session.get("status") == "running"
    )


@asynccontextmanager
async def reserve_new_session(active_sessions: dict | Callable[[], dict]):
    """
    Atomically reserve one session slot until the caller persists the session.

    The active-session provider is evaluated while holding the lock, and pending
    reservations count toward the cap so concurrent requests cannot use the
    same stale snapshot.
    """
    global _pending_sessions
    async with _lock:
        running = _running_count(active_sessions)
        effective_running = running + _pending_sessions
        if effective_running >= _MAX_CONCURRENT:
            raise HTTPException(
                429,
                f"Too many concurrent scans ({effective_running}/{_MAX_CONCURRENT}). "
                "Wait for an active session to complete.",
            )

        now = time.monotonic()
        cutoff = now - 60.0
        _recent_starts[:] = [started for started in _recent_starts if started > cutoff]
        if len(_recent_starts) >= _MAX_PER_MINUTE:
            raise HTTPException(
                429,
                f"Rate limit: max {_MAX_PER_MINUTE} new scans per minute. Retry shortly.",
            )
        _recent_starts.append(now)
        _pending_sessions += 1
    try:
        yield
    finally:
        async with _lock:
            _pending_sessions = max(0, _pending_sessions - 1)


async def check_and_record_new_session(active_sessions: dict | Callable[[], dict]) -> None:
    """Compatibility helper for callers that complete reservation immediately."""

    async with reserve_new_session(active_sessions):
        return None
