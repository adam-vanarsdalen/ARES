# ARES Architecture Notes

ARES is authorized security tooling. It is designed for systems the operator owns
or has explicit permission to assess, and every network-facing tool must remain
bounded by the configured engagement scope.

## Safety Contract

- Passive, light-active, and full modes must all enforce the same scope model.
- New OSINT, recon, red-team, and reporting tools must call `ScopeValidator`
  before making network requests or evaluating discovered targets.
- Red-team verification means non-destructive confirmation only. Do not add
  credential stuffing, default credential attempts, exploit payloads, shell
  execution, destructive writes, or data exfiltration.
- JavaScript and response analysis may report redacted secret previews and
  metadata, but must not persist raw secrets.
- External lookup failures are non-fatal. Network, API, enrichment, and model
  errors should produce coverage gaps or warnings rather than aborting an
  assessment.
- Generated scan reports, SQLite state, virtual environments, caches, and local
  agent state are runtime artifacts and must stay out of git.

## Validation

Run validation from the repository root with development dependencies installed:

```bash
python3 -m compileall -q . -x 'venv|\.venv|__pycache__'
python3 -m pytest tests/ -q
```

If the host `python3` environment does not have `pytest`, install
`requirements-dev.txt` into the active environment or run the commands with the
project virtual environment first on `PATH`.
