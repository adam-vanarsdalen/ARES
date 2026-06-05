"""Plugin contracts for ARES tool extensions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field


VALID_CATEGORIES = {"osint", "recon", "verify", "report", "export", "lab"}
VALID_RISK_LEVELS = {"passive", "light_active", "active", "advanced", "lab"}


@dataclass
class ToolResult:
    plugin_name: str
    status: str
    findings: list[dict] = field(default_factory=list)
    evidence_records: list[dict] = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


class AresToolPlugin(ABC):
    name = ""
    version = "0.0.0"
    category = "recon"
    risk_level = "passive"
    requires_scope = False
    requires_roe = False
    config_schema: dict = {}
    output_schema: dict = {}

    def validate_config(self, config: dict | None = None) -> dict:
        config = dict(config or {})
        unknown = set(config) - set(self.config_schema)
        if unknown:
            raise ValueError(f"Unknown plugin config keys: {', '.join(sorted(unknown))}")
        return config

    def is_allowed(self, context: dict) -> tuple[bool, str]:
        if self.requires_scope and context.get("scope_validator") is None:
            return False, "Plugin requires a scope validator."
        if self.requires_scope and context.get("target"):
            valid, reason = context["scope_validator"].validate(context["target"])
            if not valid:
                return False, reason
        if self.requires_roe and context.get("roe") is None:
            return False, "Plugin requires a loaded Rules of Engagement policy."
        profile = str(context.get("profile", "recon"))
        if self.risk_level == "advanced" and profile not in {"advanced", "custom", "lab"}:
            return False, "Plugin requires advanced, custom, or lab profile."
        if self.risk_level == "lab" and profile != "lab":
            return False, "Plugin requires lab profile."
        return True, "Plugin is permitted by its declared requirements."

    @abstractmethod
    def run(self, target: str, context: dict) -> ToolResult | dict:
        raise NotImplementedError
