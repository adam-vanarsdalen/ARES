from plugins.base import AresToolPlugin, ToolResult


class InventorySummaryPlugin(AresToolPlugin):
    name = "inventory_summary"
    version = "1.0.0"
    category = "report"
    risk_level = "passive"
    requires_scope = False
    requires_roe = False
    config_schema = {}
    output_schema = {"coverage": {"assets": "integer"}}

    def run(self, target: str, context: dict) -> ToolResult:
        assets = context.get("assets", [])
        return ToolResult(
            plugin_name=self.name,
            status="complete",
            coverage={"target": target, "assets": len(assets)},
        )


def plugin():
    return InventorySummaryPlugin()
