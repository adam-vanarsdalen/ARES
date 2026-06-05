"""
Simple in-process rate limiter for ARES.

Provides:
  - Global concurrent session cap  (ARES_MAX_CONCURRENT_SESSIONS, default 5)
  - Per-minute new-session cap     (ARES_MAX_SESSIONS_PER_MINUTE, default 10)
"""

import asyncio
import time

from fastapi import HTTPException
from utils.config import MAX_CONCURRENT, MAX_PER_MINUTE

_MAX_CONCURRENT = MAX_CONCURRENT
_MAX_PER_MINUTE = MAX_PER_MINUTE

_recent_starts: list[float] = []
_lock = asyncio.Lock()


async def check_and_record_new_session(active_sessions: dict) -> None:
    """
    Call before creating a session. Raises HTTP 429 if limits are exceeded.
    Mutates _recent_starts to record the current request timestamp.
    """
    async with _lock:
        running = sum(
            1 for session in active_sessions.values()
            if session.get("status") == "running"
        )
        if running >= _MAX_CONCURRENT:
            raise HTTPException(
                429,
                f"Too many concurrent scans ({running}/{_MAX_CONCURRENT}). "
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
