"""Queue hardening tests."""

import asyncio

import pytest

import server
from utils import session_store


async def _make_full_queue(size=3):
    q = asyncio.Queue(maxsize=size)
    for i in range(size):
        q.put_nowait({"type": "log", "data": {"i": i}, "timestamp": ""})
    return q


@pytest.mark.asyncio
async def test_overflow_drops_oldest_not_newest():
    session_id = "queue-overflow"
    server.event_queues[session_id] = await _make_full_queue(3)
    try:
        server.push_event(session_id, "new", {"v": 99})
        events = []
        q = server.event_queues[session_id]
        while not q.empty():
            events.append(q.get_nowait())

        types = [e["type"] for e in events]
        assert "warn" in types
        assert "new" in types
        assert types.count("log") < 3
    finally:
        server.event_queues.pop(session_id, None)


@pytest.mark.asyncio
async def test_normal_push_preserves_order():
    q = asyncio.Queue(maxsize=10)
    for i in range(5):
        q.put_nowait({"type": "log", "data": {"i": i}, "timestamp": ""})
    results = []
    while not q.empty():
        results.append(q.get_nowait()["data"]["i"])
    assert results == list(range(5))


@pytest.mark.asyncio
async def test_status_endpoint_reports_queue_depth():
    session_id = "status-session"
    session_store.init_db()
    session_store.delete_session(session_id)
    session_store.create_session(session_id, "example.com", "full", "2026-01-01T00:00:00Z")
    server.event_queues[session_id] = asyncio.Queue(maxsize=10)
    server.event_queues[session_id].put_nowait({"type": "log", "data": {}, "timestamp": ""})
    try:
        out = await server.get_status(session_id)
        assert out["session_id"] == session_id
        assert out["target"] == "example.com"
        assert out["status"] == "running"
        assert out["queue_depth"] == 1
        assert out["report_ready"] is False
    finally:
        server.event_queues.pop(session_id, None)
        session_store.delete_session(session_id)


@pytest.mark.asyncio
async def test_status_endpoint_missing_session_returns_404():
    with pytest.raises(Exception) as exc:
        await server.get_status("missing-status-session")
    assert exc.value.status_code == 404
