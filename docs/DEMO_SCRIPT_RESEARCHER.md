# Researcher Demo Script

1. Start ARES with advanced verification enabled and a local Ollama model.
2. Run `make demo-lab-up`.
3. Confirm `http://127.0.0.1:8080/health`.
4. Run `make demo-run-researcher` and open the returned session in the dashboard.
5. Show the `ADVANCED` profile and loaded researcher RoE.
6. In Results, show non-destructive CORS, redirect, clickjacking, host-header,
   method, API-doc, and protected-path verification statuses.
7. Open the verification ledger and show `next_best_manual_test`.
8. Open the finding review queue, mark one candidate `needs_review`, add an
   analyst note, then mark a synthetic control response `false_positive`.
9. Open Scorecard and compare exposure, evidence quality, false-positive risk,
   and VDP reportability.
10. Download Markdown and JSON; show evidence IDs, hashes, reproduction steps,
    and no raw secrets.
11. Run `make demo-lab-down`.
