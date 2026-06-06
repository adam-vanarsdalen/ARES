from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_gitignore_contains_required_hygiene_rules():
    rules = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    for required in (
        "venv/",
        ".venv/",
        "__MACOSX/",
        "ares.db",
        "reports/*",
        "!reports/.gitkeep",
    ):
        assert required in rules


def test_clean_packaging_contract_exists():
    script = ROOT / "scripts" / "package_clean.sh"
    assert script.is_file()
    assert script.stat().st_mode & 0o111
    assert (ROOT / "reports" / ".gitkeep").is_file()
