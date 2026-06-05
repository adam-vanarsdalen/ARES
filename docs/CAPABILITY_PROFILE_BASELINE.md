# ARES Capability Profile Baseline

Date: 2026-06-05

## Readiness Summary

ARES is ready for the capability-profile star pass. The current codebase already
has strong scope enforcement, authenticated API access, bounded collection,
non-destructive verification helpers, redacted secret handling, structured
evidence primitives, and a passing test suite.

The primary missing foundation is a canonical capability and Rules of
Engagement (RoE) decision layer. Existing mode checks and feature flags are
distributed across `server.py`, `pipeline.py`, `utils/config.py`, and individual
tools. Prompt 01 should centralize those decisions before advanced, lab, or
custom capabilities are added.

## Current Modes

The API and pipeline currently accept:

- `passive_only`
- `osint_only`
- `light_active`
- `recon_only`
- `full`

These modes control phase execution and nmap/red-team availability. They are not
yet the requested capability profiles (`passive`, `recon`, `advanced`, `lab`,
and `custom`), and they do not load or enforce an RoE policy.

## Current Safety Controls

- `X-ARES-Key` authentication protects non-dashboard API routes.
- Session rate limits and concurrency caps protect assessment creation.
- `ScopeValidator` checks domains, IP ranges, and URLs before network actions.
- Discovered InternetDB/reverse-IP assets do not automatically expand scope.
- Network collection is bounded by timeouts, budgets, wordlist limits, graph
  limits, and per-phase caps.
- Red-team helpers are non-destructive and do not attempt credentials.
- PUT/DELETE checks are disabled by default and use zero-body requests when
  enabled.
- Raw discovered secrets are removed before SSE, reports, JSON, SARIF,
  CycloneDX, or session results are emitted.
- The manual secret endpoint is disabled by default and returns only a redacted
  preview without persistence or provider API calls.
- Reports include a run manifest with scope, mode, tools, caps, coverage gaps,
  external sources, and safety flags.

## Current Advanced Verification

Existing verification helpers include:

- open redirect marker reflection checks
- OPTIONS/TRACE checks
- optional zero-body PUT/DELETE checks
- clickjacking header validation
- host-header reflection checks
- API endpoint enumeration
- authentication-panel discovery without credential attempts
- exposed-path, CORS, and missing-header checks
- TLS certificate, protocol, and cipher posture checks
- version/framework disclosure checks
- attack graph and evidence-backed kill-chain synthesis

These tools currently rely on global config and pipeline routing. They are not
yet gated by profile, RoE method/path allowlists, operator intent, or a unified
audit decision record.

## Current Lab and Demo Support

- Local targets such as `127.0.0.1` can be scoped and probed.
- HTTP probing supports common local application ports including 3000 and 8080.
- Existing documentation and tests support authorized demo targets.

Missing:

- a lab profile
- lab-safe target classification
- signed or explicit lab manifests
- localhost/demo-only exploit simulations
- packaged demo applications and scripted scenarios

No real-target exploit payload automation currently exists.

## Existing Evidence and Reporting

- `utils/evidence_model.py` provides stable IDs for assets and evidence.
- Coverage records distinguish success, partial, skipped, and failed states in
  several phases.
- Reports are generated as Markdown, JSON, SARIF, and CycloneDX-style output.
- Asset inventory and per-asset recon context are retained.
- Attack graph nodes represent routes, forms, APIs, TLS findings, external
  enrichment, version disclosure, and verification results.

Missing:

- append-only evidence ledger
- artifact hashes and reproducibility commands
- finding lifecycle/state transitions
- reportability scoring and false-positive reduction
- STIX, OSCAL, VEX, and CSAF exports
- OpenTelemetry traces and deterministic replay

## Missing Prerequisites

Prompt 01 should establish:

1. Canonical capability profile enum and resolution.
2. Machine-readable RoE schema and validation.
3. A central authorization decision API combining profile, RoE, scope,
   capability, HTTP method, path, and target classification.
4. Audit records for allowed, denied, and skipped actions.
5. Backward-compatible mapping from existing modes to profiles.
6. Profile/RoE data in API requests, sessions, manifests, and reports.

Later prompts still need:

- advanced-verification gating
- lab-safe target and manifest enforcement
- safe/moderate/custom Nuclei profiles
- volatile secret workbench
- evidence ledger and finding lifecycle
- standards and government-oriented exports
- plugin/tool registry
- telemetry/replay
- executive scorecard and demo labs

## Fragile Files

- `pipeline.py`: large orchestration module with mode, collection, recon,
  verification, manifest, and reporting responsibilities.
- `server.py`: API request/session schema and profile/RoE ingestion point.
- `utils/config.py`: centralized environment configuration with import-time
  values; tests reload modules when changing environment variables.
- `tools/redteam_verification.py`: risky-method behavior currently depends on a
  global flag instead of per-engagement authorization.
- `utils/scope_validator.py`: critical enforcement boundary; changes require
  broad regression coverage.
- `utils/report_generator.py`: multiple output formats depend on consistent
  redaction and manifest behavior.
- `tools/attack_graph.py`: consumes many evolving report structures.
- `ARES_dashboard.html`: single-file React UI with API request construction and
  authenticated downloads.

The worktree already contains the uncommitted prior expansion pass. New changes
must preserve and build on those files rather than reverting them.

## Baseline Validation

Required host commands:

- `python3 -m compileall -q . -x 'venv|\.venv|__pycache__'`: passed.
- `python3 -m pytest tests/ -q`: unavailable because the host Python 3.14
  environment does not have `pytest`.

Project virtual environment:

- `PATH=venv/bin:$PATH python3 -m compileall -q . -x 'venv|\.venv|__pycache__'`:
  passed.
- `PATH=venv/bin:$PATH python3 -m pytest tests/ -q`: passed.

## Prompt 01 Decision

Safe to continue: **yes**.

Prompt 01 should add the capability/RoE foundation without enabling new network
actions. Advanced or lab actions should remain unavailable until their
respective later prompts add explicit gates and tests.
