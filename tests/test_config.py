"""Config module tests."""


def test_config_loads_defaults():
    import utils.config as c

    assert isinstance(c.SESSION_TTL, int)
    assert c.SESSION_TTL > 0
    assert isinstance(c.HTTP_PROBE_TOTAL_BUDGET, float)


def test_as_dict_has_no_secrets():
    import utils.config as c

    d = c.as_dict()
    assert "API_KEY" not in str(d).upper()
    assert isinstance(d["max_concurrent"], int)


def test_env_override(monkeypatch):
    monkeypatch.setenv("ARES_SESSION_TTL_SECONDS", "999")
    import importlib
    import utils.config as c

    importlib.reload(c)
    assert c.SESSION_TTL == 999
    monkeypatch.delenv("ARES_SESSION_TTL_SECONDS")
    importlib.reload(c)
