"""
ARES — Report Generator
Produces professional penetration test reports from agent findings.
"""

import json
import os
from datetime import datetime, timezone

from utils.exporters import build_cyclonedx_report, build_sarif_report


def generate_report(
    target: str,
    osint_report: dict,
    vuln_report: dict,
    redteam_report: dict,
    output_dir: str = "reports",
    run_manifest: dict | None = None,
) -> str:
    """Generate a full penetration test report in Markdown + JSON."""

    os.makedirs(output_dir, exist_ok=True)
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace("/", "_")
    filename = f"{output_dir}/ARES_Report_{safe_target}_{timestamp}.md"

    risk_level = redteam_report.get("overall_risk", "UNKNOWN")
    risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(risk_level, "⚪")
    run_manifest = run_manifest or osint_report.get("run_manifest") or vuln_report.get("run_manifest") or redteam_report.get("run_manifest") or {}

    # ── Executive Summary ─────────────────────────────────────────────────────
    md = f"""# ARES Security Assessment Report
**Target:** `{target}`
**Date:** {now.strftime("%Y-%m-%d %H:%M UTC")}
**Overall Risk:** {risk_emoji} **{risk_level}**

---

## Executive Summary

{osint_report.get("summary", "No summary available.")}

{redteam_report.get("engagement_summary", "")}

---

## Run Manifest

```json
{json.dumps(run_manifest, indent=2)}
```

---

## Phase 1: OSINT Intelligence

### Infrastructure Overview
```json
{json.dumps(osint_report.get("infrastructure", {}), indent=2)}
```

### Discovered Subdomains
"""

    subdomains = osint_report.get("subdomains", [])
    if subdomains:
        for sub in subdomains:
            if isinstance(sub, dict):
                md += f"- `{sub.get('subdomain', '?')}` → `{sub.get('ip', 'N/A')}`\n"
            else:
                md += f"- `{sub}`\n"
    else:
        md += "_No subdomains discovered._\n"

    md += "\n### Technology Stack\n"
    tech_stack = osint_report.get("technology_stack", [])
    if tech_stack:
        for tech in tech_stack:
            if isinstance(tech, dict):
                md += f"- {tech.get('name', tech)}\n"
            else:
                md += f"- {tech}\n"
    else:
        md += "_No technology detected._\n"

    passive_urls = osint_report.get("passive_url_discovery", {})
    if passive_urls:
        robots = passive_urls.get("robots", {})
        sitemaps = passive_urls.get("sitemaps", {})
        security_txt = passive_urls.get("security_txt", {})
        suggested_dorks = passive_urls.get("suggested_dorks", [])
        md += "\n### Passive URL Discovery\n"
        md += f"- `robots.txt` status: `{robots.get('status_code', 0)}`\n"
        md += f"- Robots allow/disallow: `{len(robots.get('allow', []))}` / `{len(robots.get('disallow', []))}`\n"
        md += f"- Sitemap URLs: `{len(sitemaps.get('urls', []))}`\n"
        md += f"- `security.txt` status: `{security_txt.get('status_code', 0)}`\n"
        if suggested_dorks:
            md += "- Suggested dorks (manual review only; not executed by ARES):\n"
            for dork in suggested_dorks:
                md += f"  - `{dork}`\n"

    org_osint = osint_report.get("org_osint", {})
    if org_osint:
        md += "\n### Organization OSINT\n"
        if org_osint.get("organization"):
            md += f"- Organization: `{org_osint.get('organization')}`\n"
        if org_osint.get("registrar"):
            md += f"- Registrar: `{org_osint.get('registrar')}`\n"
        emails = org_osint.get("emails", [])
        abuse_emails = org_osint.get("abuse_emails", [])
        if emails:
            md += f"- Contact emails: {', '.join(f'`{email}`' for email in emails)}\n"
        if abuse_emails:
            md += f"- Abuse emails: {', '.join(f'`{email}`' for email in abuse_emails)}\n"

    md += f"\n### OSINT Risk Score: {osint_report.get('risk_score', 'N/A')} / 10\n"
    coverage_gaps = osint_report.get("coverage_gaps", [])
    if coverage_gaps:
        md += "\n### Coverage Gaps\n"
        for gap in coverage_gaps:
            md += f"- `{gap}`\n"

    assets = osint_report.get("assets", [])
    if assets:
        md += "\n### Asset Inventory\n"
        for asset in assets[:12]:
            md += f"- **{asset.get('asset_type', 'asset')}** `{asset.get('name', asset.get('value', ''))}`"
            if asset.get("value") and asset.get("value") != asset.get("name"):
                md += f" → `{asset.get('value')}`"
            md += f" [{asset.get('confidence', 'MEDIUM')}]\n"

    structured_inventory = osint_report.get("asset_inventory", [])
    if structured_inventory:
        md += "\n### Per-Host Asset Inventory\n"
        for asset in structured_inventory[:20]:
            tech_hints = asset.get("tech_stack", []) or asset.get("cpe_strings", [])
            md += (
                f"- `{asset.get('host', '')}` source=`{asset.get('source', '')}` "
                f"priority=`{asset.get('priority', 9)}` in_scope=`{asset.get('in_scope', False)}` "
                f"notable_findings=`{asset.get('notable_findings_count', 0)}`"
            )
            if asset.get("url"):
                md += f" url=`{asset.get('url')}`"
            if tech_hints:
                md += f" tech=`{', '.join(str(t) for t in tech_hints[:3])}`"
            md += "\n"

    secret_queue = osint_report.get("secret_verification_queue", [])
    if secret_queue:
        md += "\n### Exposed Secret Verification Queue\n"
        md += "_Manual verification only. ARES does not store raw secrets or call provider APIs with discovered values._\n"
        for item in secret_queue[:10]:
            md += (
                f"- `{item.get('secret_id', '')}` **{item.get('type', 'Secret')}** "
                f"from `{item.get('source_url', '') or 'unknown source'}` "
                f"[confidence={item.get('confidence', 'MEDIUM')}, preview=`{item.get('value_preview', '')}`]\n"
            )
            md += f"  Safe check: {item.get('recommended_safe_check', '')}\n"

    # ── Vulnerability Assessment ──────────────────────────────────────────────
    md += "\n---\n\n## Phase 2: Vulnerability Assessment\n\n### Critical Findings\n"

    critical = vuln_report.get("critical_findings", [])
    if critical:
        for f in critical:
            md += f"#### 🔴 {f.get('title', f.get('id', 'Finding'))}\n"
            md += f"> {f.get('description', '')}\n\n"
            if f.get("cvss_score"):
                md += f"**CVSS Score:** {f['cvss_score']}  \n"
            if f.get("affected"):
                md += f"**Affected:** {f['affected']}\n"
            if f.get("priority"):
                md += f"**Priority:** {f['priority']}  \n"
            if f.get("confidence"):
                md += f"**Confidence:** {f['confidence']}\n"
            md += "\n"
    else:
        md += "_No critical findings._\n"

    md += "\n### High Findings\n"
    high = vuln_report.get("high_findings", [])
    if high:
        for f in high:
            score = f" (CVSS: {f['cvss_score']})" if f.get("cvss_score") else ""
            md += f"- **{f.get('title', f.get('id', 'Finding'))}{score}** — {f.get('description', '')[:200]}\n"
    else:
        md += "_No high findings._\n"

    md += "\n### Medium Findings\n"
    medium = vuln_report.get("medium_findings", [])
    if medium:
        for f in medium:
            score = f" (CVSS: {f['cvss_score']})" if f.get("cvss_score") else ""
            md += f"- **{f.get('title', f.get('id', 'Finding'))}{score}** — {f.get('description', '')[:200]}\n"
    else:
        md += "_No medium findings._\n"

    md += "\n### CVE Matches\n"
    cve_matches = vuln_report.get("cve_matches", [])
    if cve_matches:
        for cve in cve_matches:
            md += (f"- `{cve.get('id', 'N/A')}` "
                   f"(CVSS: {cve.get('cvss_score', 'N/A')}, {cve.get('severity', '?')}) — "
                   f"{cve.get('description', '')[:120]}\n")
    else:
        md += "_No CVE matches found._\n"

    service_inventory = vuln_report.get("service_inventory", [])
    if service_inventory:
        md += "\n### Service Inventory\n"
        for service in service_inventory[:10]:
            md += f"- `{service.get('name', service.get('value', 'service'))}` [{service.get('confidence', 'MEDIUM')}]\n"

    version_disclosure = vuln_report.get("version_disclosure") or vuln_report.get("_version_disclosure", {})
    if version_disclosure:
        md += "\n### Version Disclosure & Framework Exposure\n"
        findings = version_disclosure.get("findings", [])
        protected = [item for item in version_disclosure.get("paths", []) if item.get("protected")]
        meaningful = [item for item in findings if item.get("risk") in {"medium", "high", "critical"}]
        if meaningful:
            for finding in meaningful[:10]:
                md += (
                    f"- **{finding.get('severity', finding.get('risk', 'INFO').upper())}** "
                    f"`{finding.get('path', '')}` - {finding.get('description', '')}"
                )
                if finding.get("framework_hint"):
                    md += f" [{finding.get('framework_hint')}]\n"
                else:
                    md += "\n"
                if finding.get("evidence_preview"):
                    md += f"  Evidence preview: `{finding.get('evidence_preview')[:180]}`\n"
        else:
            md += "_No high or medium framework exposure findings._\n"
        if protected:
            md += "\nProtected existence evidence:\n"
            for item in protected[:10]:
                md += f"- `{item.get('path', '')}` returned HTTP `{item.get('status_code', 0)}`\n"

    additional_targets = vuln_report.get("additional_targets") or vuln_report.get("_additional_targets", {})
    if additional_targets and additional_targets.get("targets"):
        md += "\n### Additional Recon Targets\n"
        coverage = additional_targets.get("coverage", {})
        md += (
            f"- Targets selected: `{coverage.get('targets_total', len(additional_targets.get('targets', [])))}`; "
            f"probed: `{coverage.get('probed', 0)}`; failed: `{coverage.get('failed', 0)}`\n"
        )
        for item in additional_targets.get("probes", [])[:10]:
            md += (
                f"- `{item.get('url', '')}` [{item.get('source', 'unknown')}, "
                f"priority {item.get('priority', '?')}] HTTP `{item.get('status_code', 0)}`"
            )
            if item.get("tech_signals"):
                md += f" - {', '.join(item.get('tech_signals', [])[:3])}"
            md += "\n"

    tls_posture = vuln_report.get("tls_audit") or vuln_report.get("_tls_audit", {})
    if tls_posture:
        cert = tls_posture.get("certificate", {})
        md += "\n### TLS Posture\n"
        md += f"- Target: `{tls_posture.get('target', '')}:{tls_posture.get('port', 443)}`\n"
        if cert:
            md += f"- Certificate subject: `{cert.get('subject', '')}`\n"
            md += f"- Issuer: `{cert.get('issuer', '')}`\n"
            md += f"- Expires: `{cert.get('not_after', '')}`"
            if cert.get("days_until_expiry") is not None:
                md += f" ({cert.get('days_until_expiry')} days)\n"
            else:
                md += "\n"
        if tls_posture.get("selected_tls_version"):
            md += f"- Selected TLS: `{tls_posture.get('selected_tls_version')}` / `{tls_posture.get('selected_cipher', '')}`\n"
        protocols = tls_posture.get("protocols", {})
        if protocols:
            md += "- Protocol support: " + ", ".join(f"`{k}: {v}`" for k, v in protocols.items()) + "\n"
        if tls_posture.get("findings"):
            md += "\nTLS remediation suggestions:\n"
            for finding in tls_posture.get("findings", [])[:8]:
                md += f"- **{finding.get('severity', 'MEDIUM')}** {finding.get('title', 'TLS finding')}: {finding.get('description', '')}\n"

    prioritized = vuln_report.get("prioritized_findings", [])
    if prioritized:
        md += "\n### Prioritized Findings\n"
        for finding in prioritized[:8]:
            md += (
                f"- **{finding.get('priority', 'P4')}** {finding.get('title', 'Finding')} "
                f"[{finding.get('severity', 'MEDIUM')}, confidence={finding.get('confidence', 'MEDIUM')}]"
            )
            if finding.get("affected"):
                md += f" → `{finding.get('affected')}`"
            md += "\n"

    # ── Red Team Results ──────────────────────────────────────────────────────
    md += "\n---\n\n## Phase 3: Red Team Results\n\n### Confirmed Vulnerabilities\n"
    if redteam_report.get("profile_badge"):
        md += f"\n**Capability Profile:** `{redteam_report.get('profile_badge')}`\n\n"

    confirmed = redteam_report.get("confirmed_vulnerabilities", [])
    if confirmed:
        for v in confirmed:
            md += f"#### ✅ {v.get('name', 'Vulnerability')}\n"
            md += f"- **Severity:** {v.get('severity', 'N/A')}\n"
            md += f"- **Exploitable:** {'Yes' if v.get('exploitable') else 'Unconfirmed'}\n"
            md += f"- **Evidence:** {v.get('evidence', 'N/A')}\n\n"
    else:
        md += "_No confirmed vulnerabilities._\n"

    md += "\n### Proof of Concepts\n"
    pocs = redteam_report.get("proof_of_concepts", [])
    if pocs:
        for poc in pocs:
            md += f"- **{poc.get('name', 'PoC')}:** `{poc.get('payload', 'N/A')}` → {poc.get('result', 'N/A')}\n"
    else:
        md += "_No proof of concepts._\n"

    validation_summary = redteam_report.get("validation_summary", {})
    if validation_summary:
        md += "\n### Validation Summary\n"
        md += f"- Tests executed: {validation_summary.get('tests_executed', 0)}\n"
        md += f"- Confirmed findings: {validation_summary.get('confirmed_count', 0)}\n"
        for status, count in validation_summary.get("status_counts", {}).items():
            if count:
                md += f"- `{status}`: {count}\n"
        if validation_summary.get("coverage_gaps"):
            md += f"- Coverage gaps: {', '.join(validation_summary.get('coverage_gaps', []))}\n"

    verification_results = redteam_report.get("verification_results", [])
    if verification_results:
        md += "\n### Verification Ledger\n"
        for item in verification_results:
            result = item.get("result", {})
            md += (
                f"- **{result.get('status', 'needs_manual_followup')}** "
                f"{item.get('finding', item.get('test', 'Verification'))}"
            )
            if result.get("matched_rule"):
                md += f" (`{result.get('matched_rule')}`)"
            md += "\n"
            if result.get("reason"):
                md += f"  - Governance: {result.get('reason')}\n"
            if result.get("next_best_manual_test"):
                md += f"  - Next manual test: {result.get('next_best_manual_test')}\n"

    # ── Recommendations ───────────────────────────────────────────────────────
    md += "\n---\n\n## Recommendations\n\n"
    recs = redteam_report.get("recommendations", [])
    if recs:
        for rec in recs:
            if isinstance(rec, str):
                md += f"- {rec}\n"
            else:
                md += f"- **{rec.get('priority', 'MEDIUM')}:** {rec.get('recommendation', '')}\n"
    else:
        md += "_No recommendations generated._\n"

    # ── Raw Data ──────────────────────────────────────────────────────────────
    # Strip internal keys before dumping
    osint_clean = {k: v for k, v in osint_report.items() if not k.startswith("_")}
    vuln_clean = {k: v for k, v in vuln_report.items()}
    redteam_clean = dict(redteam_report)

    md += f"""
---

## Raw Data

<details>
<summary>Full OSINT Report (JSON)</summary>

```json
{json.dumps(osint_clean, indent=2)[:3000]}
```
</details>

<details>
<summary>Full Vulnerability Report (JSON)</summary>

```json
{json.dumps(vuln_clean, indent=2)[:3000]}
```
</details>

<details>
<summary>Full Red Team Report (JSON)</summary>

```json
{json.dumps(redteam_clean, indent=2)[:3000]}
```
</details>

---
*Generated by ARES — Autonomous Recon & Exploitation System*
*For authorized security testing only.*
"""

    with open(filename, "w") as f:
        f.write(md)

    # Also save JSON
    json_filename = filename.replace(".md", ".json")
    with open(json_filename, "w") as f:
        json.dump({
            "target": target,
            "timestamp": timestamp,
            "overall_risk": risk_level,
            "run_manifest": run_manifest,
            "osint": osint_clean,
            "vulnerabilities": vuln_clean,
            "redteam": redteam_clean
        }, f, indent=2)

    sarif_filename = filename.replace(".md", ".sarif.json")
    with open(sarif_filename, "w") as f:
        json.dump(build_sarif_report(target, vuln_clean, redteam_clean), f, indent=2)

    cdx_filename = filename.replace(".md", ".cdx.json")
    with open(cdx_filename, "w") as f:
        json.dump(build_cyclonedx_report(target, osint_clean, vuln_clean), f, indent=2)

    return filename
