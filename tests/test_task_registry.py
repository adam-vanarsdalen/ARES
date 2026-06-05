"""Task registry and graceful shutdown tests."""

import asyncio

import pytest


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
