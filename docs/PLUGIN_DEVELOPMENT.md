# ARES Plugin Development

Plugins implement `plugins.base.AresToolPlugin` and return `ToolResult`.

Required declarations:

- `name`, `version`
- `category`: `osint`, `recon`, `verify`, `report`, `export`, or `lab`
- `risk_level`: `passive`, `light_active`, `active`, `advanced`, or `lab`
- `requires_scope` and `requires_roe`
- `config_schema` and `output_schema`

Active network plugins must require scope. Advanced and lab plugins must require
Rules of Engagement. External plugins are disabled unless
`ARES_ENABLE_EXTERNAL_PLUGINS=true`; built-ins remain available.

Use `PluginRegistry.run_plugin()` rather than calling a plugin directly. The
registry validates configuration and policy, normalizes output, records runtime,
and creates redacted evidence for findings that do not supply their own records.

Plugins must not persist raw secrets, bypass scope, perform destructive writes,
or claim exploitation without evidence.
