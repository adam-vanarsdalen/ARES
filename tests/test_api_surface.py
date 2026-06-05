"""API surface smoke tests - no real network, no Ollama."""

import os
import sys
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

os.environ["ARES_API_KEY"] = "smoke-key"
os.environ["ARES_ENV"] = "dev"
os.environ["ARES_DB_PATH"] = ":memory:"

_HEADERS = {"X-ARES-Key": "smoke-key"}


@pytest.fixture(scope="module")
def client():
    os.environ["ARES_API_KEY"] = "smoke-key"
    os.environ["ARES_ENV"] = "dev"
    os.environ["ARES_DB_PATH"] = ":memory:"
    for mod in list(sys.modules.keys()):
        if mod == "server" or mod == "utils.config" or mod == "utils.session_store":
            sys.modules.pop(mod, None)
    with patch("ollama_compat.check_ollama", return_value={"running": True, "models": []}):
        import server

        server.init_db()
        return TestClient(server.app)


def test_root(client):
    r = client.get("/", headers=_HEADERS)
    assert r.status_code == 200
    assert "endpoints" in r.json()


def test_browser_root_serves_dashboard(client):
    r = client.get("/", headers={"Accept": "text/html"})
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]


def test_dashboard_path_is_public(client):
    r = client.get("/ARES_dashboard.html")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]


def test_health(client):
    r = client.get("/health", headers=_HEADERS)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "config" in data


def test_list_sessions_empty(client):
    r = client.get("/assess", headers=_HEADERS)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_get_unknown_session_404(client):
    r = client.get("/assess/nonexistent/results", headers=_HEADERS)
    assert r.status_code == 404


def test_status_unknown_session_404(client):
    r = client.get("/assess/nonexistent/status", headers=_HEADERS)
    assert r.status_code == 404


def test_unauthenticated_401(client):
    r = client.get("/health")
    assert r.status_code == 401


def test_stop_unknown_session_404(client):
    r = client.post("/assess/nonexistent/stop", headers=_HEADERS)
    assert r.status_code == 404


def test_start_assessment_strips_target_whitespace(client):
    import server

    async def fake_pipeline(*args, **kwargs):
        return None

    with (
        patch.object(server, "get_ollama_status", return_value={"running": True, "models": []}),
        patch.object(server, "run_pipeline_background", side_effect=fake_pipeline),
    ):
        r = client.post(
            "/assess",
            headers={**_HEADERS, "Content-Type": "application/json"},
            json={"target": " demo.testfire.net ", "domains": [" demo.testfire.net ", " *.testfire.net "], "mode": " full "},
        )
    assert r.status_code == 200
    data = r.json()
    assert data["target"] == "demo.testfire.net"
    session = server.get_session(data["session_id"])
    assert session["target"] == "demo.testfire.net"


def test_start_assessment_normalizes_url_target(client):
    import server

    async def fake_pipeline(*args, **kwargs):
        return None

    with (
        patch.object(server, "get_ollama_status", return_value={"running": True, "models": []}),
        patch.object(server, "run_pipeline_background", side_effect=fake_pipeline),
    ):
        r = client.post(
            "/assess",
            headers={**_HEADERS, "Content-Type": "application/json"},
            json={"target": "https://demo.testfire.net/default.aspx", "domains": ["https://demo.testfire.net"], "mode": "full"},
        )
    assert r.status_code == 200
    data = r.json()
    assert data["target"] == "demo.testfire.net"
    session = server.get_session(data["session_id"])
    assert session["target"] == "demo.testfire.net"


def test_start_assessment_auto_scopes_literal_ip_target(client):
    import server

    async def fake_pipeline(*args, **kwargs):
        return None

    with (
        patch.object(server, "get_ollama_status", return_value={"running": True, "models": []}),
        patch.object(server, "run_pipeline_background", side_effect=fake_pipeline),
    ):
        r = client.post(
            "/assess",
            headers={**_HEADERS, "Content-Type": "application/json"},
            json={"target": "127.0.0.1", "domains": [], "ip_ranges": [], "mode": "full"},
        )
    assert r.status_code == 200
    assert r.json()["target"] == "127.0.0.1"
