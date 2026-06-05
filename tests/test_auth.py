"""Tests for API key middleware."""

import os
import sys

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("ARES_API_KEY", "test-key-123")
os.environ.setdefault("ARES_ENV", "dev")


def _client():
    os.environ["ARES_API_KEY"] = "test-key-123"
    os.environ["ARES_ENV"] = "dev"
    for mod in list(sys.modules.keys()):
        if "server" in mod or "pipeline" in mod or "ollama_compat" in mod or mod == "utils.config":
            sys.modules.pop(mod, None)
    import server

    return TestClient(server.app)


def test_unauthenticated_health_returns_401():
    c = _client()
    r = c.get("/health")
    assert r.status_code == 401


def test_authenticated_health_returns_200():
    c = _client()
    r = c.get("/health", headers={"X-ARES-Key": "test-key-123"})
    assert r.status_code == 200


def test_root_is_public():
    c = _client()
    r = c.get("/")
    assert r.status_code == 200


def test_wrong_key_returns_401():
    c = _client()
    r = c.get("/health", headers={"X-ARES-Key": "wrong"})
    assert r.status_code == 401


def test_missing_key_refuses_prod_start(monkeypatch):
    monkeypatch.delenv("ARES_API_KEY", raising=False)
    monkeypatch.setenv("ARES_ENV", "prod")
    for mod in list(sys.modules.keys()):
        if mod == "server" or mod == "utils.config":
            sys.modules.pop(mod, None)
    with pytest.raises(RuntimeError, match="ARES_API_KEY"):
        import server  # noqa: F401
    sys.modules.pop("server", None)
