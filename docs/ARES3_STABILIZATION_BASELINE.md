# ARES 3 Stabilization Baseline

Date: 2026-06-06

## Validation

- `python3 -m compileall -q . -x 'venv|\.venv|__pycache__'`: passed.
- Host `python3 -m pytest tests/ -q`: unavailable because the Homebrew Python
  environment does not contain pytest.
- Project venv `PATH=venv/bin:$PATH python3 -m pytest tests/ -q`: passed.

## Red Team Agent Wiring

`tools/redteam_verification.py` implements:

- `test_open_redirect`
- `test_http_methods`
- `test_clickjacking`
- `test_host_header_injection`
- `enumerate_api_endpoints`
- `discover_auth_panels`

`agents/redteam_agent.py` currently exposes only:

- `discover_admin_panels`
- `test_cors_misconfiguration`
- `compile_redteam_report`

`execute_tool()` dispatches only those three names. It does not dispatch the six
implemented verification helpers. Admin-panel and CORS behavior is duplicated
inside the agent rather than using the shared verification module.

## Standards Mapping

All four expected files exist:

- `mappings/attack_mapping.yaml`
- `mappings/owasp_asvs_mapping.yaml`
- `mappings/nist_800_53_mapping.yaml`
- `mappings/ssdf_mapping.yaml`

`utils/standards_mapping.py` opens every file without handling a missing
directory, missing file, unreadable file, malformed YAML, or unexpected YAML
shape. A packaging omission can therefore fail report finalization.

## Nuclei

`pipeline.py` calls `run_nuclei()` during every recon phase. The runner returns
`skipped` when disabled, but the unnecessary call still creates disabled-tool
noise and makes disabled behavior harder to reason about.

## CVE Import Path

`pipeline.py` imports `fetch_cve_data` from `tools.network_tools`.
`tools.network_tools.fetch_cve_data()` is only a compatibility wrapper that
imports the real implementation from `tools.cve_sources`.

## Secret Handling

`tools/secret_workbench.py` accepts only operator-supplied volatile values.
Results explicitly set:

- `not_persisted=true`
- `raw_value_stored=false`
- `automatic_discovered_secret_use=false`

The red-team agent prompt does not yet explain that discovered, redacted secret
indicators must become manual verification candidates and must never be
automatically tested.

## Repository and Runtime Artifacts

The working tree is clean. `git ls-files` shows no tracked virtualenv, cache,
macOS metadata, local database, generated report, or audit-log artifacts except
the intentional `reports/.gitkeep`.

Local ignored runtime artifacts currently exist:

- `.venv/`
- `.pytest_cache/`
- multiple `__pycache__/` directories
- `.DS_Store`
- `ares.db`
- generated reports and replay JSON under `reports/`

`.gitignore` covers the required classes. `.dockerignore` covers most classes,
but does not explicitly exclude `.pytest_cache/`, `ares.db-*`, general generated
report/replay files, or audit logs.

## Immediate Risks

1. The LLM red-team agent cannot call most implemented verification tools.
2. Missing mapping assets can crash standards enrichment.
3. Disabled Nuclei runs through the adapter and emits avoidable skip behavior.
4. The CVE import path obscures source ownership.
5. Secret-handling instructions are less explicit than the implemented safety model.
6. Local packaging contexts can include cache, database sidecars, replay, or
   audit artifacts if ignore rules are incomplete.

The stabilization prompts are applicable and safe to proceed in order.
