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
