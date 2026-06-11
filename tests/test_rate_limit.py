"""Rate limiter unit tests - no network required."""

import asyncio
import time

import pytest

import utils.rate_limit as rl


def _reset():
    rl._recent_starts.clear()
    rl._pending_sessions = 0


@pytest.mark.asyncio
async def test_allows_first_session():
    _reset()
    await rl.check_and_record_new_session({})


@pytest.mark.asyncio
async def test_concurrent_cap():
    _reset()
    sessions = {str(i): {"status": "running"} for i in range(5)}
    with pytest.raises(Exception) as exc:
        await rl.check_and_record_new_session(sessions)
    assert exc.value.status_code == 429


@pytest.mark.asyncio
async def test_per_minute_cap():
    _reset()
    now = time.monotonic()
    rl._recent_starts.extend([now] * rl._MAX_PER_MINUTE)
    with pytest.raises(Exception) as exc:
        await rl.check_and_record_new_session({})
    assert exc.value.status_code == 429


@pytest.mark.asyncio
async def test_old_entries_expire():
    _reset()
    old = time.monotonic() - 61
    rl._recent_starts.extend([old] * rl._MAX_PER_MINUTE)
    await rl.check_and_record_new_session({})


@pytest.mark.asyncio
async def test_concurrent_reservations_cannot_bypass_limit(monkeypatch):
    _reset()
    monkeypatch.setattr(rl, "_MAX_CONCURRENT", 1)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def first():
        async with rl.reserve_new_session(lambda: {}):
            entered.set()
            await release.wait()

    task = asyncio.create_task(first())
    await entered.wait()
    with pytest.raises(Exception) as exc:
        async with rl.reserve_new_session(lambda: {}):
            pass
    assert exc.value.status_code == 429
    release.set()
    await task
