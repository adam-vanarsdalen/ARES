from pathlib import Path

from tools.network_tools import FALLBACK_SUBDOMAIN_WORDLIST, load_subdomain_wordlist
from utils.config import SUBDOMAIN_WORDLIST_PATH


REQUIRED_WORDS = {
    "auth", "sso", "oauth", "login", "idp", "okta", "pay", "checkout",
    "billing", "admin", "admin-api", "api", "api-dev", "dev-api",
    "staging", "stage", "uat", "preprod", "qa", "corp", "internal",
    "intranet", "vpn", "dr", "backup", "backups", "grafana",
    "prometheus", "kibana", "elastic", "jenkins", "gitlab", "jira",
    "confluence", "docs", "status", "support", "help", "portal", "app",
    "mobile", "assets", "cdn", "mail", "smtp", "mx", "mfa", "identity",
    "dashboard", "console", "beta", "test", "demo", "sandbox",
}


def test_bundled_subdomain_wordlist_loads_at_default_cap():
    words = load_subdomain_wordlist(SUBDOMAIN_WORDLIST_PATH, 500)

    assert len(words) == 500
    assert len(words) == len(set(words))
    assert all(word == word.lower() for word in words)


def test_bundled_subdomain_wordlist_contains_required_high_value_words():
    words = set(load_subdomain_wordlist(SUBDOMAIN_WORDLIST_PATH, 1000))

    assert REQUIRED_WORDS.issubset(words)


def test_subdomain_wordlist_dedupe_preserves_order(tmp_path):
    path = tmp_path / "subs.txt"
    path.write_text("\n# comment\nAPI\napi\nAdmin\n admin \nlogin\n", encoding="utf-8")

    assert load_subdomain_wordlist(str(path), 10) == ["api", "admin", "login"]


def test_subdomain_wordlist_max_cap(tmp_path):
    path = tmp_path / "subs.txt"
    path.write_text("\n".join(f"sub{i}" for i in range(10)), encoding="utf-8")

    assert load_subdomain_wordlist(str(path), 3) == ["sub0", "sub1", "sub2"]


def test_missing_subdomain_wordlist_uses_internal_fallback():
    words = load_subdomain_wordlist(str(Path("missing") / "nope.txt"), 4)

    assert words == FALLBACK_SUBDOMAIN_WORDLIST[:4]
