import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parent.parent
LABS = ROOT / "labs"


def test_lab_manifest_validates():
    manifest = yaml.safe_load((LABS / "lab_manifest.yaml").read_text(encoding="utf-8"))
    labs = manifest["labs"]
    assert "ares-demo-lab" in labs["docker_services"]
    assert labs["cidrs"]
    assert labs["scenarios"]
    assert all(target["lab_safe"] is True for target in labs["targets"])
    assert all(target["url"].startswith("http://127.0.0.1:") for target in labs["targets"])


def test_expected_findings_shape_validates():
    expected = json.loads((LABS / "expected_findings.json").read_text(encoding="utf-8"))
    assert expected["deterministic"] is True
    assert len(expected["findings"]) >= 7
    assert all({"id", "title", "path", "minimum_status"} <= finding.keys() for finding in expected["findings"])


def test_demo_services_contain_no_real_secrets():
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in LABS.rglob("*")
        if path.is_file() and path.suffix in {".py", ".md", ".yaml", ".yml", ".json", ".txt"}
    )
    forbidden = ("sk_live_", "ghp_", "github_pat_", "AKIA")
    assert not any(marker in combined for marker in forbidden)
    assert "LAB_ONLY_NOT_A_REAL_SECRET" in combined


def test_docker_compose_config_validates_or_skips():
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI unavailable")
    result = subprocess.run(
        ["docker", "compose", "-f", str(LABS / "docker-compose.yml"), "config"],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if "is not a docker command" in result.stderr.lower():
        pytest.skip("Docker Compose unavailable")
    assert result.returncode == 0, result.stderr
