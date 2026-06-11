"""Dockerfile structure tests."""

import os


def test_dockerfile_exists():
    assert os.path.isfile("Dockerfile"), "Dockerfile missing"


def test_dockerfile_non_root():
    content = open("Dockerfile").read()
    assert "USER ares" in content, "Dockerfile must run as non-root user"


def test_dockerfile_has_healthcheck():
    content = open("Dockerfile").read()
    assert "HEALTHCHECK" in content


def test_dockerignore_excludes_secrets():
    assert os.path.isfile(".dockerignore"), ".dockerignore missing"
    content = open(".dockerignore").read()
    assert ".env" in content
    assert "venv/" in content
    assert "reports/" in content


def test_compose_exists():
    assert os.path.isfile("docker-compose.yml")


def test_compose_requires_api_key():
    content = open("docker-compose.yml").read()
    assert "ARES_API_KEY:?" in content or "ARES_API_KEY}" in content


def test_default_compose_keeps_ollama_internal_and_ares_localhost_only():
    content = open("docker-compose.yml").read()
    assert '"11434:11434"' not in content
    assert '"0.0.0.0:11434:11434"' not in content
    assert '127.0.0.1:8001:8001' in content
    assert "ARES_OLLAMA_BASE_URL=http://ollama:11434" in content
    assert "ollama/ollama:latest" not in content
