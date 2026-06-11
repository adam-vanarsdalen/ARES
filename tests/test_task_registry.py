"""Task registry and graceful shutdown tests."""

import asyncio

import pytest

import server
from utils import session_store


@pytest.mark.asyncio
async def test_task_registered_and_cleaned_up():
    """Simulate a fast pipeline completing and verify cleanup."""
    registry: dict[str, asyncio.Task] = {}

    async def fake_pipeline(sid):
        await asyncio.sleep(0)

    sid = "test-session"
    task = asyncio.create_task(fake_pipeline(sid))
    registry[sid] = task

    def on_done(t, s=sid):
        registry.pop(s, None)

    task.add_done_callback(on_done)
    await asyncio.gather(task, return_exceptions=True)
    assert sid not in registry


@pytest.mark.asyncio
async def test_cancelled_task_removed():
    registry: dict[str, asyncio.Task] = {}

    async def slow():
        await asyncio.sleep(100)

    sid = "cancel-me"
    task = asyncio.create_task(slow())
    registry[sid] = task

    def on_done(t, s=sid):
        registry.pop(s, None)

    task.add_done_callback(on_done)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert sid not in registry


@pytest.mark.asyncio
async def test_stop_endpoint_cancels_running_task_and_preserves_partial_results():
    sid = "cancel-running-assessment"
    session_store.delete_session(sid)
    session_store.create_session(sid, "example.com", "full", "now")
    session_store.update_session(
        sid,
        status="running",
        results={"osint": {"partial": True}},
        abort=False,
    )
    server.event_queues[sid] = asyncio.Queue()
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def slow_pipeline():
        started.set()
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    task = asyncio.create_task(slow_pipeline())
    server._pipeline_tasks[sid] = task
    await started.wait()
    try:
        response = await server.stop_assessment(sid)
        session = session_store.get_session(sid)
        assert response["status"] == "stopped"
        assert cancelled.is_set()
        assert task.cancelled()
        assert session["status"] == "stopped"
        assert session["results"]["osint"]["partial"] is True
        event = server.event_queues[sid].get_nowait()
        assert event["type"] == "stopped"
    finally:
        server._pipeline_tasks.pop(sid, None)
        server.event_queues.pop(sid, None)
        session_store.delete_session(sid)
