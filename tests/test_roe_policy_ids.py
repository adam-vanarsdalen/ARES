import pytest

from utils.roe import load_roe_policy, resolve_roe_policy_path


POLICY = """
engagement:
  name: Test Policy
  allowed_domains: [example.com]
  allowed_profiles: [recon]
"""


def test_valid_policy_id_loads_from_approved_directory(tmp_path):
    (tmp_path / "valid.yaml").write_text(POLICY, encoding="utf-8")
    policy = load_roe_policy("valid", str(tmp_path))
    assert policy.name == "Test Policy"
    assert policy.allowed_domains == ["example.com"]


@pytest.mark.parametrize("policy_id", ["../secret", "/tmp/secret", "nested/policy", "..", "."])
def test_policy_id_rejects_traversal_and_absolute_paths(tmp_path, policy_id):
    with pytest.raises(ValueError):
        resolve_roe_policy_path(policy_id, str(tmp_path))


def test_unknown_policy_id_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="Unknown"):
        load_roe_policy("missing", str(tmp_path))


def test_symlink_escaping_policy_root_is_rejected(tmp_path):
    outside = tmp_path.parent / "outside-policy.yaml"
    outside.write_text(POLICY, encoding="utf-8")
    link = tmp_path / "escape.yaml"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="outside"):
        load_roe_policy("escape", str(tmp_path))
