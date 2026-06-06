import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read_text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_key_files_have_expected_multiline_structure():
    assert len(_read_text(".gitignore").splitlines()) > 10
    assert len(_read_text("requirements.txt").splitlines()) > 5
    assert _read_text("pytest.ini").startswith("[pytest]\n")
    assert _read_text("scripts/package_clean.sh").startswith(
        "#!/usr/bin/env bash\n"
    )
    assert len(_read_text("pipeline.py").splitlines()) > 200
    assert len(_read_text("server.py").splitlines()) > 100


def test_key_files_use_lf_without_collapsed_escaped_newlines():
    paths = (
        ".gitignore",
        ".dockerignore",
        "requirements.txt",
        "requirements-dev.txt",
        "pytest.ini",
        "scripts/package_clean.sh",
        "run.sh",
        "pipeline.py",
        "server.py",
    )
    for path in paths:
        data = (ROOT / path).read_bytes()
        text = data.decode("utf-8")
        lines = text.splitlines()

        assert b"\r\n" not in data, f"{path} contains CRLF line endings"
        assert not (
            len(lines) < 5 and text.count("\\n") > 5
        ), f"{path} appears collapsed with escaped newlines"


def test_packaging_script_and_report_placeholder_are_present():
    script = ROOT / "scripts" / "package_clean.sh"
    assert script.is_file()
    assert os.access(script, os.X_OK)
    assert (ROOT / "reports" / ".gitkeep").is_file()
