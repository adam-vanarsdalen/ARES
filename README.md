# ARES - Autonomous Recon & Intelligence System

![Python](https://img.shields.io/badge/python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green)
![License](https://img.shields.io/badge/license-MIT-blue)

ARES is a security assessment platform for authorized operators who need a streaming recon pipeline, attack graph construction, AI-assisted kill chain analysis, and report exports that are useful in both engineering and security workflows. It combines passive OSINT, active service discovery, JavaScript intelligence, CVE and EPSS enrichment, MITRE ATT&CK mapping, SARIF/CycloneDX export, and a FastAPI/SSE backend designed for a browser dashboard or API clients.

## Capabilities

| Area | What ARES Does |
|------|----------------|
| Passive OSINT | DNS, WHOIS, certificate transparency through crt.sh, and bounded subdomain enumeration |
| Active recon | nmap port scan, HTTP probing, technology fingerprinting, CPE extraction, and common misconfiguration checks |
| JavaScript intelligence | Endpoint extraction, redacted secret detection, cloud resource references, inline script analysis, and application route discovery |
| Vulnerability correlation | NVD CVE lookup and EPSS exploitation probability scoring for prioritization |
| Attack graph | Asset/finding graph construction with MITRE ATT&CK technique tagging |
| Kill chains | AI-driven kill chain analysis and risk synthesis through Ollama-compatible models |
| Reporting | Markdown, JSON, SARIF 2.1, and CycloneDX-style export files under `reports/` |
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

## Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ARES_API_KEY` | string | none | Required static API key for authenticated routes. Never commit real values. |
| `ARES_ENV` | string | `prod` | Runtime mode. In `prod`, startup refuses an empty API key. |
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
| `ARES_MAX_CONCURRENT_SESSIONS` | integer | `5` | Global cap on running assessments. |
| `ARES_MAX_SESSIONS_PER_MINUTE` | integer | `10` | New assessment rate limit. |
| `ARES_EVENT_QUEUE_SIZE` | integer | `1000` | In-memory SSE event queue size per session. |
| `ARES_SAFE_TARGETS` | comma list | demo targets | Demo/CI-only scope bypass for known public test hosts. Never add internal hosts in production. |
| `ARES_DOCKER` | boolean | `0` | When set to `1`, `run.sh` skips local virtualenv setup. |

Variables present in `.env.example`:

- `ARES_API_KEY`
- `ARES_ENV`
- `ARES_OLLAMA_MODEL`
- `ARES_ALLOWED_ORIGINS`
- `ARES_DB_PATH`
- `ARES_SESSION_TTL_SECONDS`
- `ARES_HTTP_PROBE_TOTAL_BUDGET_S`
- `ARES_MISCONFIG_TOTAL_BUDGET_S`
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
