"""Session store unit tests."""

import os
import time

os.environ["ARES_DB_PATH"] = ":memory:"

import utils.session_store as ss


def setup_function():
    ss._DB_PATH = ":memory:"
    ss._memory_conn = None
    ss.init_db()


def test_create_and_get():
    ss.create_session("s1", "example.com", "full", "2026-01-01T00:00:00Z")
    s = ss.get_session("s1")
    assert s["target"] == "example.com"
    assert s["status"] == "running"
    assert s["abort"] is False


def test_update_status():
    ss.create_session("s2", "example.com", "full", "2026-01-01T00:00:00Z")
    ss.update_session("s2", status="complete")
    assert ss.get_session("s2")["status"] == "complete"


def test_update_results():
    ss.create_session("s3", "example.com", "full", "2026-01-01T00:00:00Z")
    ss.update_session("s3", results={"risk": "HIGH"})
    assert ss.get_session("s3")["results"]["risk"] == "HIGH"


def test_get_missing_returns_none():
    assert ss.get_session("nonexistent") is None


def test_list_recent():
    ss.create_session("s4", "a.com", "full", "2026-01-01T00:00:00Z")
    ss.create_session("s5", "b.com", "full", "2026-01-02T00:00:00Z")
    items = ss.list_recent_sessions()
    targets = [s["target"] for s in items]
    assert "a.com" in targets and "b.com" in targets


def test_prune():
    ss.create_session("s6", "old.com", "full", "2026-01-01T00:00:00Z")
    ss.update_session("s6", status="complete", completed_at=time.time() - 7200)
    ss.prune_old_sessions(3600)
    assert ss.get_session("s6") is None
