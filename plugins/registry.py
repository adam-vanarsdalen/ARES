"""Plugin registration, discovery, safety validation, and execution."""

from __future__ import annotations

import importlib
import pkgutil
import time

from plugins.base import AresToolPlugin, ToolResult, VALID_CATEGORIES, VALID_RISK_LEVELS
from utils.config import ENABLE_EXTERNAL_PLUGINS
from utils.evidence_ledger import create_evidence_record


class PluginRegistry:
    def __init__(self, allow_external: bool | None = None):
        self.allow_external = ENABLE_EXTERNAL_PLUGINS if allow_external is None else allow_external
        self._plugins: dict[str, AresToolPlugin] = {}

    def register_plugin(self, plugin: AresToolPlugin, *, builtin: bool = False) -> None:
        if not isinstance(plugin, AresToolPlugin):
            raise TypeError("Plugin must implement AresToolPlugin.")
        if not plugin.name:
            raise ValueError("Plugin name is required.")
        if plugin.category not in VALID_CATEGORIES or plugin.risk_level not in VALID_RISK_LEVELS:
            raise ValueError("Plugin category or risk level is invalid.")
        network_capable = plugin.category in {"osint", "recon", "verify", "lab"} and plugin.risk_level != "passive"
        if network_capable and not plugin.requires_scope:
            raise ValueError("Active network plugins must declare requires_scope=true.")
        if plugin.risk_level in {"advanced", "lab"} and not plugin.requires_roe:
            raise ValueError("Advanced and lab plugins must declare requires_roe=true.")
        if not builtin and not self.allow_external:
            raise PermissionError("External plugins are disabled.")
        self._plugins[plugin.name] = plugin

    def discover_builtin_plugins(self) -> list[str]:
        package = importlib.import_module("plugins.builtin")
        for module_info in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
            module = importlib.import_module(module_info.name)
            factory = getattr(module, "plugin", None)
            if callable(factory):
                self.register_plugin(factory(), builtin=True)
        return self.list_plugins()

    def list_plugins(self) -> list[str]:
        return sorted(self._plugins)

    def get_plugin(self, name: str) -> AresToolPlugin:
        if name not in self._plugins:
            raise KeyError(f"Unknown plugin: {name}")
        return self._plugins[name]

    def run_plugin(self, name: str, target: str, context: dict, config: dict | None = None) -> ToolResult:
        plugin = self.get_plugin(name)
        plugin.validate_config(config)
        execution_context = {**context, "target": target, "config": dict(config or {})}
        allowed, reason = plugin.is_allowed(execution_context)
        if not allowed:
            return ToolResult(plugin_name=name, status="blocked_by_policy", coverage={"reason": reason})
        started = time.perf_counter()
        try:
            raw = plugin.run(target, execution_context)
            if isinstance(raw, ToolResult):
                result = raw
            else:
                result = ToolResult(
                    plugin_name=name,
                    status=raw.get("status", "complete"),
                    findings=list(raw.get("findings", [])),
                    evidence_records=list(raw.get("evidence_records", [])),
                    coverage=dict(raw.get("coverage", {})),
                    errors=list(raw.get("errors", [])),
                )
        except Exception as exc:
            result = ToolResult(plugin_name=name, status="error", errors=[str(exc)])
        result.plugin_name = name
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        if result.findings and not result.evidence_records:
            record = create_evidence_record(
                run_id=str(context.get("run_id", "plugin-run")),
                tool_name=name,
                phase=plugin.category,
                profile=str(context.get("profile", "recon")),
                url=target,
                body=result.findings,
                body_preview=f"{len(result.findings)} normalized plugin finding(s).",
                capability_decision={"allowed": True, "reason": reason},
            )
            result.evidence_records.append(record.to_dict())
        return result


default_registry = PluginRegistry()
