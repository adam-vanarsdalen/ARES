# ARES - Authorized Recon & Evidence System

![Python](https://img.shields.io/badge/python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green)
![License](https://img.shields.io/badge/license-MIT-blue)

ARES is a capability-profile-driven security platform for authorized operators.
It combines passive intelligence, active recon, RoE-gated non-destructive
verification, lab-only exploit simulation, defensible evidence, analyst triage,
tamper-evident audit, and enterprise/government export formats.

ARES is intentionally powerful when authorization is explicit. Escalation is
controlled by profile, scope, Rules of Engagement, method/path allowlists,
operator intent, audit records, and evidence capture.

Do not commit virtualenvs or generated runtime outputs. Use
`scripts/package_clean.sh` before sharing the repo with recruiters, employers,
or reviewers. See [Clean Packaging for Sharing ARES](docs/PACKAGING.md).

## Capability Profiles

| Profile | Intended Use | Governance |
|---------|--------------|------------|
| `passive` | External intelligence with minimal target interaction | Active network and verification actions blocked |
| `recon` | Standard HTTP, TLS, service, CVE, EPSS, and asset discovery | Scope required; advanced verification blocked |
| `advanced` | Serious non-destructive verification and moderate Nuclei | Feature flag plus explicit RoE |
| `lab` | Local/demo exploit-chain simulation | Feature flag plus localhost/manifest lab target |
| `custom` | Operator-defined capability allowlist | RoE required for every declared capability |

See [docs/CAPABILITY_PROFILES.md](docs/CAPABILITY_PROFILES.md) and
[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

Full standards output uses the YAML catalogs under `mappings/`. Missing or
malformed catalogs degrade to empty mappings with warnings and never abort an
assessment.

## Capabilities

| Area | What ARES Does |
|------|----------------|
| Passive OSINT | DNS, WHOIS, certificate transparency through crt.sh, and bounded subdomain enumeration |
| Active recon | nmap port scan, HTTP probing, technology fingerprinting, CPE extraction, and common misconfiguration checks |
| JavaScript intelligence | Endpoint extraction, redacted secret detection, cloud resource references, inline script analysis, and application route discovery |
| Vulnerability correlation | NVD CVE lookup and EPSS exploitation probability scoring for prioritization |
| Attack graph | Asset/finding graph construction with MITRE ATT&CK technique tagging |
| Kill chains | AI-driven kill chain analysis and risk synthesis through Ollama-compatible models |
| Evidence and triage | Redacted evidence ledger, reproduction steps, confidence matrix, lifecycle review, and reportability scoring |
| Reporting | Markdown, JSON, SARIF, CycloneDX, STIX, OSCAL, OpenVEX, and CSAF under `reports/` |
| Governance | Capability profiles, YAML RoE, action decisions, tamper-evident audit chain, and replay timeline |
| Extensibility | Governed built-in/external plugin registry with normalized ToolResult output |
| Operations | API key auth, rate limiting, SQLite session persistence, bounded SSE queues, and Docker packaging |

## Architecture

```text
Dashboard (ARES_dashboard.html)
        |
        | HTTP + X-ARES-Key
        v
FastAPI server.py
        |
        | Server-Sent Events (SSE)
        v
ARESPipeline
        |
        +--> tools/network_tools.py
        +--> tools/cert_transparency.py
        +--> tools/js_intelligence.py
        +--> tools/epss_scoring.py
        +--> tools/attack_graph.py
        |
        v
Ollama LLM API
```

Key design decisions:

- Agent and tool events stream in real time over SSE; clients can also poll `/assess/{id}/status`.
- Scope enforcement happens at tool boundaries before network-touching operations.
- Session metadata persists in SQLite; event queues remain in memory because they are live streams.
- Pipeline tasks are tracked explicitly and cancelled gracefully during server shutdown.
- Secrets and scan outputs are ignored by default; reports are runtime artifacts, not source assets.

## Quickstart

### Prerequisites

- Docker and Docker Compose
- Ollama running locally or reachable at `ARES_OLLAMA_BASE_URL`
- An Ollama model compatible with the configured `ARES_OLLAMA_MODEL`
- Authorization to test the target you assess

### Run with Docker Compose

```bash
cp .env.example .env
# Edit .env: set ARES_API_KEY to a strong random string
docker-compose up -d
# Pull model on first run if needed
docker exec ares-ollama ollama pull qwen3.5:9b
# Open dashboard
open http://localhost:8001/ARES_dashboard.html
```

The compose stack starts:

- `ares-server` on `localhost:8001`
- `ares-ollama` on `localhost:11434`
- Persistent Docker volumes for SQLite metadata, reports, and Ollama models

### Run Locally (Dev)

```bash
cd ARES_server
cp .env.example .env
vim .env
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
ARES_ENV=dev bash run.sh
```

`run.sh` loads `.env`, requires `ARES_API_KEY`, creates `reports/`, and starts uvicorn on port `8001`.

## API Reference

All authenticated routes require this header:

```http
X-ARES-Key: <your-key>
```

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | No | Public service metadata and endpoint map |
| POST | `/assess` | Yes | Start a new assessment |
| GET | `/assess/{id}/stream` | Yes | SSE event stream for live pipeline logs and results |
| GET | `/assess/{id}/status` | Yes | Lightweight status poll with queue depth and report readiness |
| GET | `/assess/{id}/results` | Yes | Full persisted results JSON |
| GET | `/assess/{id}/report` | Yes | Download generated Markdown report |
| GET | `/assess/{id}/report?format=stix|oscal|openvex|csaf` | Yes | Download a machine-readable evidence package |
| GET | `/assess/{id}/findings` | Yes | Reportability-sorted analyst review queue |
| PATCH | `/assess/{id}/findings/{finding_id}/review` | Yes | Persist lifecycle state and analyst notes |
| POST | `/manual/verify-secret` | Yes | Advanced/custom volatile operator-supplied secret verification |
| POST | `/assess/{id}/stop` | Yes | Abort a running assessment |
| GET | `/assess` | Yes | List recent sessions |
| GET | `/health` | Yes | Server health, safe config, Ollama status, and active session count |

Example request:

```bash
curl -s \
  -H "X-ARES-Key: $ARES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","domains":["example.com","*.example.com"],"mode":"full"}' \
  http://localhost:8001/assess
```

## Mode Semantics

| Mode | Behavior |
|------|----------|
| `passive_only` | DNS, WHOIS, Certificate Transparency, InternetDB, and manual dork suggestions. No nmap, no redteam, no JS crawl, no active HTTP unless `ARES_PASSIVE_HTTP_ALLOWED=true`. |
| `osint_only` | OSINT phase only with capped HTTP probe, passive URL discovery, and JS intelligence/crawl. No nmap or redteam. |
| `light_active` | OSINT plus light recon such as version disclosure, TLS audit, additional HTTP probes, and CVE enrichment from observed HTTP evidence. No nmap or redteam. |
| `recon_only` | Target-level HTTP probe, recon, CVE enrichment, and TLS audit without OSINT expansion. No redteam. |
| `full` | All enabled phases inside caps, including non-destructive redteam verification. |

## Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ARES_API_KEY` | string | none | Required static API key for authenticated routes. Never commit real values. |
| `ARES_ENV` | string | `prod` | Runtime mode. In `prod`, startup refuses an empty API key. |
| `ARES_PROFILE` | enum | `recon` | Default capability profile: `passive`, `recon`, `advanced`, `lab`, or `custom`. |
| `ARES_ROE_POLICY_PATH` | path | none | Optional YAML Rules of Engagement policy loaded for capability decisions. |
| `ARES_ENABLE_ADVANCED_VERIFICATION` | boolean | `false` | Enables the advanced profile capability gate. RoE is still required by default. |
| `ARES_REQUIRE_ROE_FOR_ADVANCED` | boolean | `true` | Requires a loaded RoE policy before advanced verification is authorized. |
| `ARES_ENABLE_LAB_EXPLOIT_SIMULATION` | boolean | `false` | Enables lab-profile simulation capabilities; real public targets remain blocked. |
| `ARES_REQUIRE_LOCAL_TARGET_FOR_LAB_EXPLOIT_SIM` | boolean | `true` | Restricts lab simulation to localhost or RoE-declared lab targets. |
| `ARES_LAB_MANIFEST_PATH` | path | `labs/lab_manifest.yaml` | Docker service, lab CIDR, and simulation scenario allowlist. |
| `ARES_ENABLE_NUCLEI` | boolean | `false` | Enables the policy-controlled Nuclei adapter. |
| `ARES_NUCLEI_PROFILE` | enum | `safe` | Nuclei policy profile: `safe`, `moderate`, or `custom`. |
| `ARES_NUCLEI_TEMPLATE_DIR` | path | none | Optional local template directory for metadata validation. |
| `ARES_NUCLEI_ALLOWED_TEMPLATE_IDS` | comma list | none | Required explicit template allowlist for custom profile. |
| `ARES_NUCLEI_ALLOWED_TAGS` | comma list | safe tags | Tags allowed by the safe profile. |
| `ARES_NUCLEI_MODERATE_TAGS` | comma list | selected tags | Additional tags considered by moderate profile. |
| `ARES_NUCLEI_BLOCKED_TAGS` | comma list | destructive tags | Tags always excluded from real-target runs. |
| `ARES_NUCLEI_MAX_TEMPLATES` | integer | `50` | Maximum custom template IDs per run. |
| `ARES_NUCLEI_TIMEOUT_S` | seconds | `60` | Total Nuclei subprocess timeout. |
| `ARES_NUCLEI_REQUIRE_ROE_FOR_MODERATE` | boolean | `true` | Requires RoE for moderate profile. |
| `ARES_NUCLEI_REQUIRE_ALLOWLIST_FOR_CUSTOM` | boolean | `true` | Requires template IDs for custom profile. |
| `ARES_ENABLE_EXTERNAL_PLUGINS` | boolean | `false` | Enables explicitly installed external plugins; built-ins remain available. |
| `ARES_ENABLE_OTEL` | boolean | `false` | Enables optional OpenTelemetry spans when the dependency is installed. |
| `ARES_OTEL_EXPORTER_OTLP_ENDPOINT` | URL | none | Optional OTLP exporter endpoint; no secret headers are accepted here. |
| `ARES_OLLAMA_MODEL` | string | `qwen3.5:9b` | Ollama model used for synthesis and kill chain analysis. |
| `ARES_OLLAMA_BASE_URL` | URL | `http://localhost:11434` | Preferred Ollama API base URL. Compose sets this to `http://ollama:11434`. |
| `ARES_OLLAMA_BASE` | URL | `http://localhost:11434` | Legacy fallback name still accepted by config. |
| `ARES_OLLAMA_USE_NO_THINK_PROMPT` | boolean | `false` | Prepends `/no_think` in model prompts when enabled. |
| `ARES_OLLAMA_TIMEOUT_S` | integer seconds | `180` | Timeout for agent-level Ollama requests. |
| `ARES_OLLAMA_MAX_RETRIES` | integer | `2` | Retry count for agent-level Ollama requests. |
| `ARES_ALLOWED_ORIGINS` | comma list | local dashboard origins | CORS allowlist for browser clients. |
| `ARES_DB_PATH` | path | `ares.db` | SQLite session metadata database path. |
| `ARES_SESSION_TTL_SECONDS` | integer seconds | `3600` | How long completed session metadata remains before pruning. |
| `ARES_SESSION_PRUNE_INTERVAL_SECONDS` | integer seconds | `600` | Background pruning interval. |
| `ARES_HTTP_PROBE_TIMEOUT_S` | float seconds | `6.0` | GET timeout for urllib HTTP probes. |
| `ARES_HTTP_PROBE_HEAD_TIMEOUT_S` | float seconds | `3.0` | HEAD timeout for urllib/curl probe attempts. |
| `ARES_HTTP_PROBE_CURL_TIMEOUT_S` | float seconds | `8.0` | curl fallback timeout for HTTP probing. |
| `ARES_HTTP_PROBE_TOTAL_BUDGET_S` | float seconds | `15.0` | Total wall-clock budget for HTTP probing. |
| `ARES_HTTP_PROBE_MAX_BODY_BYTES` | integer bytes | `4096` | Maximum body bytes read during probes. |
| `ARES_MISCONFIG_TIMEOUT_S` | float seconds | `2.0` | Per-request timeout for misconfiguration checks. |
| `ARES_MISCONFIG_TOTAL_BUDGET_S` | float seconds | `20.0` | Total budget for common-path misconfiguration checks. |
| `ARES_JS_INTEL_BUDGET_S` | float seconds | `20.0` | Total budget for JavaScript intelligence collection. |
| `ARES_EXTERNAL_LOOKUP_TIMEOUT_S` | float seconds | `8.0` | Timeout for passive external enrichment lookups such as Shodan InternetDB. |
| `ARES_PASSIVE_HTTP_ALLOWED` | boolean | `false` | Allows robots/sitemap/security.txt HTTP fetches in `passive_only` mode. |
| `ARES_ENABLE_NMAP` | boolean | `true` | Enables `port_scan`; mode policy still disables nmap in `passive_only` and `light_active`. |
| `ARES_ENABLE_REVERSE_IP` | boolean | `false` | Enables passive HackerTarget reverse-IP enrichment. Disabled by default because ownership is unverified. |
| `ARES_REVERSE_IP_MAX_HOSTS` | integer | `50` | Maximum ownership-unverified reverse-IP hostnames retained. |
| `ARES_PASSIVE_URL_TIMEOUT_S` | float seconds | `8.0` | Per-request timeout for robots.txt, sitemap.xml, and security.txt discovery. |
| `ARES_SITEMAP_MAX_CHILDREN` | integer | `5` | Maximum child sitemaps fetched from a sitemap index. |
| `ARES_PASSIVE_URL_MAX` | integer | `100` | Maximum in-scope passive URLs retained for crawling/reporting. |
| `ARES_SUBDOMAIN_WORDLIST_PATH` | path | `wordlists/subdomains-500.txt` | Subdomain candidate wordlist path, relative to the repo root unless absolute. |
| `ARES_SUBDOMAIN_WORDLIST_MAX` | integer | `500` | Maximum subdomain candidates loaded from the configured wordlist. |
| `ARES_VERSION_DISCLOSURE_TIMEOUT_S` | float seconds | `8.0` | Per-request timeout for version disclosure and framework exposure probes. |
| `ARES_EVIDENCE_PREVIEW_MAX_CHARS` | integer | `500` | Maximum evidence preview characters retained after redaction. |
| `ARES_RECON_ADDITIONAL_TARGET_MAX` | integer | `20` | Maximum OSINT-discovered HTTP targets probed during recon. |
| `ARES_ASSET_INVENTORY_MAX_HTTP_PROBES` | integer | `20` | Maximum high-priority in-scope host assets probed during OSINT inventory enrichment. |
| `ARES_TLS_TIMEOUT_S` | float seconds | `8.0` | Timeout for TLS certificate/protocol checks. |
| `ARES_TLS_ADDITIONAL_TARGET_MAX` | integer | `5` | Maximum high-priority additional HTTPS targets audited for TLS posture. |
| `ARES_ENABLE_RISKY_METHOD_CHECKS` | boolean | `false` | Enables zero-body PUT/DELETE method checks. Disabled by default. |
| `ARES_API_ENUM_MAX_PATHS` | integer | `12` | Maximum capped API discovery paths checked by redteam verification. |
| `ARES_REDTEAM_MAX_VERIFICATIONS` | integer | `20` | Maximum non-destructive redteam verification actions per assessment. |
| `ARES_ATTACK_GRAPH_MAX_ROUTE_NODES` | integer | `50` | Maximum route nodes included in the attack graph before overflow metadata is recorded. |
| `ARES_ATTACK_GRAPH_MAX_FORM_NODES` | integer | `30` | Maximum form nodes included in the attack graph before overflow metadata is recorded. |
| `ARES_ATTACK_GRAPH_MAX_API_NODES` | integer | `50` | Maximum API endpoint nodes included in the attack graph before overflow metadata is recorded. |
| `ARES_NVD_API_KEY` | string | none | Optional NVD API key. Never commit real values. |
| `ARES_NVD_MIN_DELAY_S` | float seconds | `6.5` without key, `0.8` with key | Minimum delay between uncached NVD requests. |
| `ARES_CVE_CACHE_TTL_S` | integer seconds | `86400` | In-memory CVE lookup cache TTL. |
| `ARES_ENABLE_VULNERS` | boolean | `false` | Enables optional Vulners fallback when API key is configured. |
| `ARES_VULNERS_API_KEY` | string | none | Optional Vulners API key. Never commit real values. |
| `ARES_ENABLE_MANUAL_SECRET_VERIFY` | boolean | `false` | Enables the volatile `/manual/verify-secret` workbench. Raw values are never persisted. |
| `ARES_SECRET_VERIFY_REQUIRE_ADVANCED_PROFILE` | boolean | `true` | Restricts the workbench to advanced/custom operator intent. |
| `ARES_SECRET_VERIFY_ALLOWED_PROVIDERS` | comma list | `github,aws,stripe,generic` | Provider handlers enabled for volatile verification. |
| `ARES_MAX_CONCURRENT_SESSIONS` | integer | `5` | Global cap on running assessments. |
| `ARES_MAX_SESSIONS_PER_MINUTE` | integer | `10` | New assessment rate limit. |
| `ARES_EVENT_QUEUE_SIZE` | integer | `1000` | In-memory SSE event queue size per session. |
| `ARES_SAFE_TARGETS` | comma list | demo targets | Demo/CI-only scope bypass for known public test hosts. Never add internal hosts in production. |
| `ARES_DOCKER` | boolean | `0` | When set to `1`, `run.sh` skips local virtualenv setup. |

Variables present in `.env.example`:

- `ARES_API_KEY`
- `ARES_ENV`
- `ARES_OLLAMA_MODEL`
- `ARES_PROFILE`
- `ARES_ROE_POLICY_PATH`
- `ARES_ENABLE_ADVANCED_VERIFICATION`
- `ARES_REQUIRE_ROE_FOR_ADVANCED`
- `ARES_ENABLE_LAB_EXPLOIT_SIMULATION`
- `ARES_REQUIRE_LOCAL_TARGET_FOR_LAB_EXPLOIT_SIM`
- `ARES_NUCLEI_PROFILE`
- `ARES_ALLOWED_ORIGINS`
- `ARES_DB_PATH`
- `ARES_SESSION_TTL_SECONDS`
- `ARES_HTTP_PROBE_TOTAL_BUDGET_S`
- `ARES_MISCONFIG_TOTAL_BUDGET_S`
- `ARES_EXTERNAL_LOOKUP_TIMEOUT_S`
- `ARES_PASSIVE_HTTP_ALLOWED`
- `ARES_ENABLE_NMAP`
- `ARES_ENABLE_REVERSE_IP`
- `ARES_REVERSE_IP_MAX_HOSTS`
- `ARES_PASSIVE_URL_TIMEOUT_S`
- `ARES_SITEMAP_MAX_CHILDREN`
- `ARES_PASSIVE_URL_MAX`
- `ARES_SUBDOMAIN_WORDLIST_PATH`
- `ARES_SUBDOMAIN_WORDLIST_MAX`
- `ARES_VERSION_DISCLOSURE_TIMEOUT_S`
- `ARES_EVIDENCE_PREVIEW_MAX_CHARS`
- `ARES_RECON_ADDITIONAL_TARGET_MAX`
- `ARES_ASSET_INVENTORY_MAX_HTTP_PROBES`
- `ARES_TLS_TIMEOUT_S`
- `ARES_TLS_ADDITIONAL_TARGET_MAX`
- `ARES_ENABLE_RISKY_METHOD_CHECKS`
- `ARES_API_ENUM_MAX_PATHS`
- `ARES_REDTEAM_MAX_VERIFICATIONS`
- `ARES_ATTACK_GRAPH_MAX_ROUTE_NODES`
- `ARES_ATTACK_GRAPH_MAX_FORM_NODES`
- `ARES_ATTACK_GRAPH_MAX_API_NODES`
- `ARES_NVD_API_KEY`
- `ARES_NVD_MIN_DELAY_S`
- `ARES_CVE_CACHE_TTL_S`
- `ARES_ENABLE_VULNERS`
- `ARES_VULNERS_API_KEY`
- `ARES_ENABLE_MANUAL_SECRET_VERIFY`
- `ARES_MAX_CONCURRENT_SESSIONS`
- `ARES_MAX_SESSIONS_PER_MINUTE`
- `ARES_EVENT_QUEUE_SIZE`
- `ARES_SAFE_TARGETS`

## Output Formats

ARES writes reports under `reports/` and keeps generated outputs out of source control.

- `reports/ARES_Report_<target>_<ts>.md` - human-readable assessment report
- `reports/ARES_Report_<target>_<ts>.json` - full structured output
- `reports/ARES_Report_<target>_<ts>.sarif.json` - SARIF 2.1 for IDE and CI integration
- `reports/ARES_Report_<target>_<ts>.cdx.json` - CycloneDX-style output for SBOM/VEX workflows
- `reports/ARES_Report_<target>_<ts>.stix.json` - STIX 2.1-like bundle
- `reports/ARES_Report_<target>_<ts>.oscal.json` - OSCAL assessment-results package
- `reports/ARES_Report_<target>_<ts>.openvex.json` - OpenVEX lifecycle statements
- `reports/ARES_Report_<target>_<ts>.csaf.json` - CSAF 2.0-like draft advisory
- `reports/<run_id>_replay.json` - chronological redacted audit/evidence replay

## Local Demo

```bash
make demo-lab-up
make demo-run-researcher
make demo-run-government
make demo-report
make demo-lab-down
```

The lab binds synthetic services to localhost only. See [labs/README.md](labs/README.md).

## Ollama

The default model is `qwen3.5:9b`. Start Ollama and pull the model:

```bash
ollama serve
ollama pull qwen3.5:9b
```

Set `ARES_OLLAMA_BASE_URL` and `ARES_OLLAMA_MODEL` when using another local
endpoint. Cloud-tagged models may require an Ollama subscription and can return
HTTP 403; use a locally installed model for an offline demo.

## Troubleshooting

- **401 from API:** send the configured `X-ARES-Key`.
- **Advanced action blocked:** enable `ARES_ENABLE_ADVANCED_VERIFICATION` and load an RoE that permits the profile/action.
- **Lab simulation blocked:** enable the lab flag and use localhost or a target declared in `labs/lab_manifest.yaml`.
- **Nuclei skipped:** install `nuclei`, enable `ARES_ENABLE_NUCLEI`, and select an allowed profile.
- **AI synthesis fallback:** verify Ollama is running and the configured model is locally available.
- **Global pytest missing:** run tests with `PATH=venv/bin:$PATH python3 -m pytest tests/ -q`.
- **Docker unavailable:** core tests still run; Docker build/lab startup require a running Docker engine.

## Authorized Use Only

ARES is a security assessment tool. Only run it against systems you own or targets where you have explicit written permission to test. Built-in scope enforcement reduces accidental target drift, but it is not a substitute for authorization, rules of engagement, rate limits, legal review, or responsible disclosure practices.

## Development

Run the full local test suite:

```bash
python -m pytest tests/ -q
```

In this workspace, if `python` is not on PATH, use:

```bash
PATH=venv/bin:$PATH python -m pytest tests/ -q
```

Test categories include:

- Auth middleware and protected health checks
- Rate limiting and task registry behavior
- SQLite session persistence and pruning
- SSE formatting and event queue overflow handling
- Scope validation and safe-target behavior
- HTTP probe, JavaScript intelligence, cert transparency, EPSS, and attack graph helpers
- Dockerfile and compose structure checks

## Repository Hygiene

The repository is configured to ignore:

- `.env` and `.env.*` except `.env.example`
- `venv/`, `.venv/`, `__pycache__/`, and Python bytecode
- generated reports, SARIF, CycloneDX, logs, and SQLite runtime files
- macOS metadata and editor folders

`reports/.gitkeep` preserves the runtime report directory without committing scan output.
