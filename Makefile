ARES_API_KEY ?= dev-insecure
ARES_API_URL ?= http://127.0.0.1:8001

.PHONY: demo-lab-up demo-lab-down demo-run-researcher demo-run-government demo-report

demo-lab-up:
	docker compose -f labs/docker-compose.yml up -d --build

demo-lab-down:
	docker compose -f labs/docker-compose.yml down

demo-run-researcher:
	curl -fsS -X POST "$(ARES_API_URL)/assess" -H "X-ARES-Key: $(ARES_API_KEY)" -H "Content-Type: application/json" -d '{"target":"127.0.0.1","ip_ranges":["127.0.0.1/32"],"mode":"full","profile":"advanced","roe_policy_path":"labs/researcher_roe.yaml"}'

demo-run-government:
	curl -fsS -X POST "$(ARES_API_URL)/assess" -H "X-ARES-Key: $(ARES_API_KEY)" -H "Content-Type: application/json" -d '{"target":"127.0.0.1","ip_ranges":["127.0.0.1/32"],"mode":"full","profile":"advanced","roe_policy_path":"labs/government_roe.yaml"}'

demo-report:
	@ls -1t reports/ARES_Report_127_0_0_1_*.md 2>/dev/null | head -1
