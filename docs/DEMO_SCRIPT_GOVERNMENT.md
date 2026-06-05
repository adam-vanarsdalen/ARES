# Government Reviewer Demo Script

1. Start ARES with advanced verification enabled.
2. Run `make demo-lab-up`.
3. Open `labs/government_roe.yaml` and explain allowed scope, profiles, methods,
   forbidden path, and absence of risky methods.
4. Run `make demo-run-government`.
5. Show blocked actions in the verification ledger and scorecard as evidence of
   governance rather than missing capability.
6. Open Replay and validate the chronological audit event hashes and chain head.
7. Open a finding and show ATT&CK, OWASP ASVS, NIST 800-53, and SSDF mappings,
   including the non-certification disclaimer.
8. Download:
   - `/assess/<id>/report?format=stix`
   - `/assess/<id>/report?format=oscal`
   - `/assess/<id>/report?format=openvex`
   - `/assess/<id>/report?format=csaf`
9. Show the executive scorecard: scope confidence, control coverage, exposure,
   evidence quality, remediation urgency, coverage gaps, and blocked actions.
10. Confirm all targets are localhost and all lab secrets are synthetic.
11. Run `make demo-lab-down`.
