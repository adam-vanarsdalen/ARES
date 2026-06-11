from pathlib import Path


def test_dashboard_does_not_persist_api_key_in_browser_storage():
    content = Path("ARES_dashboard.html").read_text(encoding="utf-8")
    assert "localStorage" not in content
    assert "sessionStorage" not in content
    assert 'useState("")' in content
    assert "Held in memory only" in content
    assert "console.log(apiKey" not in content


def test_dashboard_remote_scripts_have_integrity_and_csp():
    content = Path("ARES_dashboard.html").read_text(encoding="utf-8")
    assert "Content-Security-Policy" in content
    for script in ("react.production.min.js", "react-dom.production.min.js", "babel.min.js"):
        tag = next(line for line in content.splitlines() if script in line)
        assert "integrity=" in tag
        assert 'crossorigin="anonymous"' in tag
