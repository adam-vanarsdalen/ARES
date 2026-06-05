import pytest

from plugins.base import AresToolPlugin
from plugins.registry import PluginRegistry
from utils.scope_validator import Scope, ScopeValidator


class UnsafeNetworkPlugin(AresToolPlugin):
    name = "unsafe_network"
    version = "1.0"
    category = "verify"
    risk_level = "active"
    requires_scope = False

    def run(self, target, context):
        return {"status": "complete"}


class ExternalReportPlugin(AresToolPlugin):
    name = "external_report"
    version = "1.0"
    category = "report"
    risk_level = "passive"

    def run(self, target, context):
        return {
            "status": "complete",
            "findings": [{"title": "Plugin observation", "description": "Normalized output."}],
            "coverage": {"complete": True},
        }


def test_builtin_sample_plugin_registers():
    registry = PluginRegistry(allow_external=False)
    plugins = registry.discover_builtin_plugins()
    assert "inventory_summary" in plugins
    plugin = registry.get_plugin("inventory_summary")
    assert plugin.category == "report"


def test_unsafe_network_plugin_without_scope_requirement_is_rejected():
    registry = PluginRegistry(allow_external=True)
    with pytest.raises(ValueError, match="requires_scope"):
        registry.register_plugin(UnsafeNetworkPlugin())


def test_external_plugins_are_disabled_by_default():
    registry = PluginRegistry(allow_external=False)
    with pytest.raises(PermissionError, match="disabled"):
        registry.register_plugin(ExternalReportPlugin())


def test_plugin_result_normalizes_and_creates_evidence():
    registry = PluginRegistry(allow_external=True)
    registry.register_plugin(ExternalReportPlugin())
    result = registry.run_plugin(
        "external_report",
        "example.com",
        {
            "profile": "recon",
            "run_id": "run-plugin",
            "scope_validator": ScopeValidator(Scope(domains=["example.com"])),
        },
    )
    assert result.status == "complete"
    assert result.plugin_name == "external_report"
    assert result.findings[0]["title"] == "Plugin observation"
    assert result.evidence_records[0]["raw_secret_stored"] is False
    assert result.duration_ms >= 0
