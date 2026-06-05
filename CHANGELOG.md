# ARES Changelog

## [Unreleased] - Public Release Hardening

### Added
- API key authentication middleware (`X-ARES-Key` header)
- Rate limiting: concurrent session cap plus per-minute new-session cap
- SQLite-backed session persistence (sessions survive restarts)
- `asyncio.create_task` pipeline registry with graceful shutdown
- Event queue overflow handling (drops oldest, preserves newest)
- `GET /assess/{id}/status` lightweight status poll endpoint
- `utils/config.py` - single env var configuration module
- Dockerfile (non-root, healthcheck) plus docker-compose with Ollama service
- `.env.example` with all documented configuration options
- GitHub Actions CI workflow
- `ARES_SAFE_TARGETS` env var for demo/CI scope bypass

### Changed
- `os.getenv` calls consolidated into `utils/config.py`
- `BackgroundTasks` replaced with `asyncio.create_task` plus task registry
- `/health` now returns config summary without secrets

### Fixed
- `venv/`, `.venv/`, `reports/`, `__pycache__/` removed from git tracking scope
- ARES-OLLAMA artifact scaffolding excluded from the server repo
- Queue `put_nowait` no longer silently discards overflow events

### Security
- All endpoints except `GET /` require `X-ARES-Key` authentication
- Server refuses to start in prod mode without `ARES_API_KEY` set
- `.dockerignore` excludes `.env`, `ares.db`, `venv/`, `reports/`
