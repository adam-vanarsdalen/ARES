"""
ARES Async Pipeline (v4 — Elite)
Adds:
  - Certificate Transparency subdomain discovery (passive, crt.sh)
  - JavaScript intelligence extraction (endpoints, secrets, cloud refs)
  - EPSS scoring on all CVEs (exploitation probability)
  - Attack graph construction + AI kill chain analysis
  - MITRE ATT&CK technique tagging
"""

import asyncio
import json
import os
import re

from ollama_compat import OllamaClient as Anthropic, DEFAULT_MODEL, extract_first_json_object
from utils.scope_validator import Scope, ScopeValidator
from utils.evidence_model import (
    dedupe_by_key,
    enrich_finding,
    make_asset,
    make_coverage,
    make_evidence,
    merge_subdomains,
    severity_to_priority,
)
from utils.report_generator import generate_report
from tools.network_tools import (
    dns_lookup, whois_lookup, subdomain_enumerate,
    http_probe, check_common_misconfigs, port_scan, fetch_cve_data
)
from tools.cert_transparency import cert_transparency_recon
from tools.js_intelligence import js_intelligence
from tools.epss_scoring import enrich_cves_with_epss, epss_summary
from tools.attack_graph import build_attack_graph, generate_kill_chains, map_to_mitre

client = Anthropic()

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "test", "portal", "admin",
    "beta", "app", "cloud", "cdn", "git", "jenkins", "jira", "confluence",
    "gitlab", "grafana", "kibana", "monitor", "status", "docs", "help", "support",
    "shop", "store", "login", "auth", "internal", "intranet", "wiki"
]


def _clean_json(text: str) -> str:
    """Strip <think> blocks, markdown fences, then extract the first JSON object."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = re.sub(r"```(?:json)?\n?", "", text)
    text = re.sub(r"```", "", text)
    return extract_first_json_object(text.strip())


def _grounded_osint_summary(target, resolved_ip, tech_signals, ct_total, js_data, misconfigs, http_data):
    parts = []
    if resolved_ip:
        parts.append(f"{target} resolved to {resolved_ip}.")
    else:
        parts.append(f"{target} was analyzed with limited network visibility.")
    parts.append(
        f"Certificate Transparency yielded {ct_total} unique names; "
        f"JavaScript analysis found {len(js_data.get('endpoints', []))} endpoints and {len(js_data.get('secrets', []))} secrets."
    )
    if tech_signals:
        parts.append(f"Observed technologies: {', '.join(tech_signals[:5])}.")
    else:
        parts.append("No reliable technology fingerprints were captured.")
    if http_data.get("partial"):
        parts.append("HTTP probing was partial after a timeout, so stack identification may be incomplete.")
    elif http_data.get("error"):
        parts.append("HTTP probing did not return usable response data.")
    if misconfigs.get("budget_exhausted"):
        parts.append(
            f"Misconfiguration checks reached the time budget after {misconfigs.get('paths_checked', 0)}/"
            f"{misconfigs.get('paths_total', 0)} paths."
        )
    return " ".join(parts)


def _dedupe_cves(cves: list[dict]) -> list[dict]:
    deduped = []
    seen = set()
    for cve in cves:
        key = (cve.get("id"), cve.get("published"), cve.get("description"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(cve)
    return deduped


def _ground_osint_report(target, dns, whois, subdomains, http, misconfigs, ct_data, js_data, report):
    tech_signals = list(http.get("tech_signals", []))
    tech_inventory = list(http.get("tech_details", []))
    discovered_subdomains = merge_subdomains(
        subdomains.get("discovered_subdomains", []),
        ct_data.get("live_subdomains", []),
        ct_data.get("interesting_subdomains", []),
    )
    org = whois.get("fields", {}).get("Registrant Organization") or None
    cdn = "Cloudflare" if any("cloudflare" in str(t).lower() for t in tech_signals) else None
    coverage_gaps = []
    if http.get("partial"):
        coverage_gaps.append("http_probe_partial")
    elif http.get("error"):
        coverage_gaps.append("http_probe_failed")
    if misconfigs.get("budget_exhausted"):
        coverage_gaps.append("misconfig_budget_exhausted")
    if js_data.get("error"):
        coverage_gaps.append("js_collection_failed")
    risk_score = (
        len(misconfigs.get("findings", [])) * 2
        + len(js_data.get("secrets", [])) * 3
        + len(ct_data.get("interesting_subdomains", []))
        + (2 if tech_signals else 0)
        + min(2, len(misconfigs.get("restricted_findings", [])))
    )
    if coverage_gaps:
        risk_score = max(risk_score, min(6, 3 + len(coverage_gaps)))
    risk_score = min(10, max(1, risk_score))
    assets = [
        make_asset("domain", target, confidence="HIGH", in_scope=True),
    ]
    if dns.get("resolved_ip"):
        assets.append(make_asset("ip", dns["resolved_ip"], confidence="HIGH", source="dns_lookup"))
    assets.extend(
        make_asset("subdomain", item["subdomain"], value=item.get("ip", ""), confidence="MEDIUM", source="ct_or_dns")
        for item in discovered_subdomains
    )
    assets.extend(
        make_asset(
            "technology",
            tech.get("name", ""),
            value=tech.get("version", ""),
            confidence="HIGH" if tech.get("version") else "MEDIUM",
            cpe=tech.get("cpe", ""),
            vendor=tech.get("cpe", "").split(":")[0] if tech.get("cpe") else "",
            product=tech.get("cpe", "").split(":")[1] if tech.get("cpe") and ":" in tech.get("cpe", "") else "",
        )
        for tech in tech_inventory
        if tech.get("name")
    )
    evidence_log = [
        make_evidence("dns_lookup", "resolution", f"{target} resolved to {dns['resolved_ip']}", confidence="HIGH")
        for _ in [0] if dns.get("resolved_ip")
    ]
    if ct_data.get("total_unique", 0):
        evidence_log.append(
            make_evidence(
                "cert_transparency",
                "subdomain_discovery",
                f"Certificate Transparency returned {ct_data.get('total_unique', 0)} unique names",
                confidence="MEDIUM",
                interesting=ct_data.get("interesting_subdomains", []),
            )
        )
    if tech_signals:
        evidence_log.append(
            make_evidence(
                "http_probe",
                "technology_fingerprint",
                f"Observed technologies: {', '.join(tech_signals[:5])}",
                confidence="HIGH" if http.get("status_code") else "MEDIUM",
                url=http.get("url", target),
                status_code=http.get("status_code"),
            )
        )
    if misconfigs.get("findings"):
        evidence_log.append(
            make_evidence(
                "check_common_misconfigs",
                "web_exposure",
                f"Observed {len(misconfigs.get('findings', []))} exposed paths",
                confidence="HIGH",
                findings=misconfigs.get("findings", []),
            )
        )
    if js_data.get("secrets") or js_data.get("endpoints"):
        evidence_log.append(
            make_evidence(
                "js_intelligence",
                "frontend_discovery",
                f"JS analysis found {len(js_data.get('endpoints', []))} endpoints and {len(js_data.get('secrets', []))} secrets",
                confidence="HIGH",
                page_url=js_data.get("page_url", target),
            )
        )
    coverage = [
        make_coverage("osint", "dns_lookup", "success" if dns.get("resolved_ip") else "partial", resolved_ip=dns.get("resolved_ip", "")),
        make_coverage("osint", "whois_lookup", "success" if whois.get("fields") else "partial"),
        make_coverage("osint", "subdomain_enumerate", "success", discovered=len(subdomains.get("discovered_subdomains", []))),
        make_coverage("osint", "cert_transparency_recon", "success" if ct_data else "partial", discovered=ct_data.get("total_unique", 0)),
        make_coverage(
            "osint",
            "http_probe",
            "partial" if http.get("partial") else "failed" if http.get("error") and not http.get("status_code") else "success",
            details=http.get("error", ""),
            status_code=http.get("status_code"),
        ),
        make_coverage(
            "osint",
            "js_intelligence",
            "failed" if js_data.get("error") else "success",
            details=js_data.get("error", ""),
            scripts_analyzed=js_data.get("script_count", 0),
        ),
        make_coverage(
            "osint",
            "check_common_misconfigs",
            "partial" if misconfigs.get("budget_exhausted") else "success",
            details="time budget exhausted" if misconfigs.get("budget_exhausted") else "",
            findings=len(misconfigs.get("findings", [])),
        ),
    ]
    return {
        "summary": _grounded_osint_summary(
            target,
            dns.get("resolved_ip", ""),
            tech_signals,
            ct_data.get("total_unique", 0),
            js_data,
            misconfigs,
            http,
        ),
        "infrastructure": {"hosting": "Unknown", "cdn": cdn, "org": org},
        "subdomains": discovered_subdomains,
        "technology_stack": tech_signals,
        "open_ports": [],
        "risk_score": risk_score,
        "misconfig_count": len(misconfigs.get("findings", [])),
        "attack_surface_notes": (
            f"JS endpoints: {len(js_data.get('endpoints', []))}; "
            f"JS secrets: {len(js_data.get('secrets', []))}; "
            f"CT interesting subdomains: {len(ct_data.get('interesting_subdomains', []))}; "
            f"misconfig findings: {len(misconfigs.get('findings', []))}; "
            f"restricted paths: {len(misconfigs.get('restricted_findings', []))}; "
            f"page source: {js_data.get('page_url', http.get('url', target))}."
        ),
        "coverage_gaps": coverage_gaps,
        "coverage": coverage,
        "assets": dedupe_by_key(assets, ("asset_type", "name", "value")),
        "evidence_log": evidence_log,
        "technology_inventory": tech_inventory,
        "collection_summary": {
            "http_status": http.get("status_code"),
            "http_url": http.get("url", target),
            "page_url": js_data.get("page_url", http.get("url", target)),
            "ct_total_unique": ct_data.get("total_unique", 0),
            "ct_interesting": len(ct_data.get("interesting_subdomains", [])),
            "misconfig_budget_exhausted": bool(misconfigs.get("budget_exhausted")),
        },
    }


def _ground_vuln_report(target, osint, ports, cves, report):
    critical_findings = []
    high_findings = []
    medium_findings = []
    evidence_log = []
    service_inventory = []

    for port_line in ports.get("open_ports", []):
        service_inventory.append(
            make_asset("service", port_line, confidence="HIGH", source="port_scan")
        )
    if service_inventory:
        evidence_log.append(
            make_evidence(
                "port_scan",
                "service_inventory",
                f"Observed {len(service_inventory)} open services",
                confidence="HIGH",
                open_ports=ports.get("open_ports", []),
            )
        )

    for secret in osint.get("_js_data", {}).get("secrets", []):
        finding = enrich_finding({
            "title": f"Hardcoded {secret['type']} in JavaScript",
            "description": f"Value preview: {secret['value_preview']}",
            "cvss_score": 9.0 if secret.get("severity") == "CRITICAL" else 7.5,
            "affected": "Client-side JavaScript",
        }, severity="CRITICAL" if secret.get("severity") == "CRITICAL" else "HIGH",
           evidence_refs=["js_intelligence"], confidence="HIGH", exploitability="MEDIUM", business_impact="HIGH")
        if finding["cvss_score"] >= 9.0:
            critical_findings.append(finding)
        else:
            high_findings.append(finding)

    for finding in osint.get("_misconfigs", []):
        entry = enrich_finding({
            "title": f"Exposed path {finding.get('path', '')}",
            "description": f"Observed HTTP status {finding.get('status', 'unknown')}",
            "cvss_score": 7.5 if finding.get("severity") == "HIGH" else 5.0,
            "affected": finding.get("path", ""),
        }, severity="HIGH" if finding.get("severity") == "HIGH" else "MEDIUM",
           evidence_refs=["check_common_misconfigs"], confidence="HIGH", exploitability="LOW", business_impact="MEDIUM")
        if finding.get("severity") == "HIGH":
            high_findings.append(entry)
        else:
            medium_findings.append(entry)

    for cve in cves:
        entry = enrich_finding({
            "title": cve.get("id", "CVE"),
            "description": cve.get("description", ""),
            "cvss_score": cve.get("cvss_score"),
            "affected": (osint.get("technology_stack") or ["Unknown"])[0] if osint.get("technology_stack") else "Unknown",
            "epss": cve.get("epss"),
        }, severity="CRITICAL" if (cve.get("cvss_score") or 0) >= 9.0 else "HIGH" if (cve.get("cvss_score") or 0) >= 7.0 else "MEDIUM",
           evidence_refs=["fetch_cve_data"], confidence="HIGH" if cve.get("cvss_score") else "MEDIUM",
           exploitability="HIGH" if (cve.get("epss") or 0) >= 0.1 else "MEDIUM", business_impact="HIGH")
        score = cve.get("cvss_score") or 0
        if score >= 9.0:
            critical_findings.append(entry)
        elif score >= 7.0:
            high_findings.append(entry)
        elif score >= 4.0:
            medium_findings.append(entry)

    missing_headers = osint.get("_missing_security_headers", [])
    if missing_headers:
        medium_findings.append(enrich_finding({
            "title": "Missing Security Headers",
            "description": "Missing headers: " + ", ".join(missing_headers),
            "cvss_score": 5.0,
            "affected": "Web application responses",
        }, severity="MEDIUM", evidence_refs=["http_probe"], confidence="HIGH", exploitability="LOW", business_impact="MEDIUM"))

    attack_vectors = []
    if ports.get("open_ports"):
        attack_vectors.append("Exposed network services")
    if critical_findings or high_findings:
        attack_vectors.append("Public-facing application weaknesses")
    if osint.get("_js_data", {}).get("secrets"):
        attack_vectors.append("Client-side secret exposure")
    coverage_gaps = list(osint.get("coverage_gaps", []))
    if ports.get("error"):
        coverage_gaps.append("port_scan_failed")
    if cves:
        evidence_log.append(
            make_evidence(
                "fetch_cve_data",
                "vulnerability_enrichment",
                f"Matched {len(cves)} CVEs to observed technologies",
                confidence="MEDIUM" if any(not c.get("cvss_score") for c in cves) else "HIGH",
                cve_ids=[c.get("id") for c in cves],
            )
        )

    if critical_findings or high_findings or medium_findings:
        scan_summary = (
            f"Grounded assessment for {target}: "
            f"{len(critical_findings)} critical, {len(high_findings)} high, {len(medium_findings)} medium findings; "
            f"{len(cves)} CVE matches from observed components."
        )
    else:
        scan_summary = (
            f"No grounded vulnerabilities were derived from the collected evidence for {target}. "
            "This reflects current tool output and may still be incomplete if probing or scanning timed out."
        )
    if coverage_gaps:
        scan_summary += " Coverage gaps: " + ", ".join(coverage_gaps) + "."

    prioritized_findings = sorted(
        critical_findings + high_findings + medium_findings,
        key=lambda item: (
            {"P1": 0, "P2": 1, "P3": 2, "P4": 3}.get(item.get("priority", "P4"), 9),
            -(item.get("cvss_score") or 0),
        ),
    )

    return {
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "medium_findings": medium_findings,
        "attack_vectors": attack_vectors,
        "scan_summary": scan_summary,
        "coverage_gaps": coverage_gaps,
        "service_inventory": service_inventory,
        "evidence_log": evidence_log,
        "prioritized_findings": prioritized_findings,
    }


def _ground_redteam_report(target, vulns, test_results, kill_chain_data, report):
    cve_matches = vulns.get("cve_matches", [])
    all_findings = vulns.get("critical_findings", []) + vulns.get("high_findings", []) + vulns.get("medium_findings", [])
    confirmed = list((report or {}).get("confirmed_vulnerabilities", []))
    pocs = list((report or {}).get("proof_of_concepts", []))
    kill_chains = list(kill_chain_data.get("kill_chains", []))

    coverage_gaps = list(vulns.get("coverage_gaps", []))
    if vulns.get("critical_findings"):
        overall_risk = "CRITICAL"
    elif vulns.get("high_findings"):
        overall_risk = "HIGH"
    elif vulns.get("medium_findings"):
        overall_risk = "MEDIUM"
    elif coverage_gaps:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    recommendations = []
    for cve in cve_matches[:5]:
        if cve.get("id"):
            recommendations.append({
                "priority": severity_to_priority("CRITICAL" if (cve.get("cvss_score") or 0) >= 9.0 else "HIGH", cve.get("cvss_score"), cve.get("epss")),
                "recommendation": f"Patch {cve['id']} on affected public-facing components.",
            })
    for finding in vulns.get("critical_findings", []) + vulns.get("high_findings", []):
        title = finding.get("title", "").lower()
        if "hardcoded" in title and "javascript" in title:
            recommendations.append({"priority": "P1", "recommendation": "Rotate exposed client-side secrets and remove them from shipped JavaScript."})
        elif "exposed path" in title:
            recommendations.append({"priority": "P2", "recommendation": f"Restrict access to {finding.get('affected', 'sensitive paths')} and remove publicly exposed files."})
    for finding in vulns.get("medium_findings", []):
        if "missing security headers" in finding.get("title", "").lower():
            recommendations.append({"priority": "P3", "recommendation": finding.get("description", "Implement missing security headers.")})
    if not recommendations:
        recommendations.append({"priority": "P3", "recommendation": "Repeat validation for slow or filtered endpoints and review manual testing coverage before treating the target as low risk."})
    elif coverage_gaps:
        recommendations.append({"priority": "P3", "recommendation": "Scan coverage was incomplete; repeat validation for timed-out or partially scanned surfaces before treating the target as low risk."})

    deduped = []
    seen = set()
    for rec in recommendations:
        key = (rec.get("priority"), rec.get("recommendation"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(rec)

    finding_by_title = {f.get("title", ""): f for f in all_findings}
    for test in test_results:
        result = test.get("result", {})
        test_name = test.get("test", "")
        finding_name = test.get("finding", test_name)
        finding = finding_by_title.get(finding_name, {})
        score = finding.get("cvss_score", 0) or 0
        if score >= 9.0:
            severity = "CRITICAL"
        elif score >= 7.0:
            severity = "HIGH"
        elif score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        if test_name == "exposed_path" and result.get("confirmed"):
            confirmed.append({
                "name": finding_name or f"Exposed path {result.get('path', '')}",
                "severity": severity,
                "evidence": f"{result.get('url', result.get('path', 'Path'))} returned HTTP {result.get('status_code')}.",
                "exploitable": False,
            })
            pocs.append({
                "name": f"Path validation for {result.get('path', finding.get('affected', 'path'))}",
                "payload": result.get("url", ""),
                "result": f"Observed HTTP {result.get('status_code')} while verifying the exposed path.",
            })
        elif test_name == "missing_security_headers" and result.get("missing_headers_confirmed"):
            missing = ", ".join(result.get("missing_headers_confirmed", []))
            confirmed.append({
                "name": finding_name or "Missing Security Headers",
                "severity": severity,
                "evidence": f"Confirmed missing headers: {missing}.",
                "exploitable": False,
            })
            pocs.append({
                "name": "Header verification",
                "payload": result.get("url", ""),
                "result": f"Response was missing: {missing}.",
            })
        elif test_name == "cors" and result.get("misconfigured"):
            confirmed.append({
                "name": finding_name or "CORS misconfiguration",
                "severity": severity,
                "evidence": f"Access-Control-Allow-Origin reflected as {result.get('acao')!r}.",
                "exploitable": False,
            })
        elif test_name == "default_credentials" and result.get("accessible_panels"):
            panels = ", ".join(result.get("accessible_panels", []))
            pocs.append({
                "name": "Admin panel discovery",
                "payload": panels,
                "result": "Accessible admin/login paths were discovered and require manual credential verification.",
            })

    unique_confirmed = []
    seen_confirmed = set()
    for item in confirmed:
        key = (item.get("name"), item.get("evidence"))
        if key in seen_confirmed:
            continue
        seen_confirmed.add(key)
        unique_confirmed.append(item)

    unique_pocs = []
    seen_pocs = set()
    for item in pocs:
        key = (item.get("name"), item.get("payload"), item.get("result"))
        if key in seen_pocs:
            continue
        seen_pocs.add(key)
        unique_pocs.append(item)

    return {
        "confirmed_vulnerabilities": unique_confirmed,
        "kill_chains": kill_chains,
        "proof_of_concepts": unique_pocs,
        "overall_risk": overall_risk,
        "engagement_summary": (
            f"Grounded red team summary for {target}: "
            f"{len(unique_confirmed)} confirmed vulnerabilities, {len(all_findings)} evidence-backed findings, "
            f"{len(kill_chains)} kill chains, and {len(test_results)} verification actions."
            + (f" Coverage gaps remain: {', '.join(coverage_gaps)}." if coverage_gaps else "")
        ),
        "recommendations": deduped[:6],
        "validation_summary": {
            "tests_executed": len(test_results),
            "confirmed_count": len(unique_confirmed),
            "coverage_gaps": coverage_gaps,
        },
    }


class ARESPipeline:
    def __init__(self, target, scope, mode, session, log_fn, phase_fn, emit_fn):
        self.target = target.strip()
        self.scope = scope
        self.mode = mode.strip()
        self.session = session
        self.log = log_fn
        self.phase = phase_fn
        self.emit = emit_fn
        self.validator = ScopeValidator(scope)

    def aborted(self):
        return self.session.get("abort", False)

    async def run(self) -> dict:
        osint_data, recon_data, redteam_data = {}, {}, {}

        # ── Phase 1: OSINT ────────────────────────────────────────────────────
        self.phase("osint", "active", "Gathering intelligence...")
        osint_data = await self._run_osint()
        self.emit("results_update", {"phase": "osint", "data": osint_data})
        sub_count = len(osint_data.get("subdomains", [])) + len(osint_data.get("_ct_subdomains", []))
        self.phase("osint", "done", f"{sub_count} subdomains, {osint_data.get('_js_endpoints_count', 0)} JS endpoints")

        if self.aborted() or self.mode == "osint_only":
            return self._finalize(osint_data, {}, {})

        # ── Phase 2: Recon ────────────────────────────────────────────────────
        self.phase("recon", "active", "Hunting CVEs & misconfigs...")
        recon_data = await self._run_recon(osint_data)
        self.emit("results_update", {"phase": "recon", "data": recon_data})
        crit = len(recon_data.get("critical_findings", []))
        high = len(recon_data.get("high_findings", []))
        p1 = recon_data.get("_epss_summary", {}).get("p1_immediate", 0)
        self.phase("recon", "done", f"{crit} critical, {high} high, {p1} P1-immediate CVEs")

        if self.aborted() or self.mode == "recon_only":
            return self._finalize(osint_data, recon_data, {})

        # ── Phase 3: Red Team ─────────────────────────────────────────────────
        self.phase("redteam", "active", "Testing + building kill chains...")
        redteam_data = await self._run_redteam(recon_data, osint_data)
        self.emit("results_update", {"phase": "redteam", "data": redteam_data})
        chain_risk = redteam_data.get("overall_risk", "?")
        chains = len(redteam_data.get("kill_chains", []))
        self.phase("redteam", "done", f"Risk: {chain_risk}, {chains} kill chains mapped")

        return self._finalize(osint_data, recon_data, redteam_data)

    def _finalize(self, osint, recon, redteam):
        self.log("ORCH", "Generating assessment report...", "blue")
        try:
            reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
            report_path = generate_report(
                target=self.target,
                osint_report=osint,
                vuln_report=recon,
                redteam_report=redteam,
                output_dir=reports_dir
            )
            self.log("SUCCESS", f"Report saved: {report_path}", "green")
        except Exception as e:
            report_path = None
            self.log("WARN", f"Report generation failed: {e}", "orange")
        return {"osint": osint, "recon": recon, "redteam": redteam, "report_path": report_path}

    # ── OSINT Phase ───────────────────────────────────────────────────────────
    async def _run_osint(self) -> dict:
        target = self.target
        self.log("OSINT", f"Initializing OSINT agent for {target}", "")
        await asyncio.sleep(0.1)

        # DNS
        self.log("TOOL", f"dns_lookup({target})", "dim")
        dns_data = await asyncio.to_thread(dns_lookup, target, self.validator)
        self.emit("tool_result", {"tool": "dns_lookup", "data": dns_data})
        if self.aborted(): return {}

        # WHOIS
        self.log("TOOL", f"whois_lookup({target})", "dim")
        whois_data = await asyncio.to_thread(whois_lookup, target, self.validator)
        self.emit("tool_result", {"tool": "whois_lookup", "data": whois_data})
        if self.aborted(): return {}

        # Subdomain brute force
        self.log("TOOL", f"subdomain_enumerate({target}, {len(SUBDOMAIN_WORDLIST)} words)", "dim")
        subdomain_data = await asyncio.to_thread(
            subdomain_enumerate, target, SUBDOMAIN_WORDLIST, self.validator
        )
        found_subs = subdomain_data.get("discovered_subdomains", [])
        for sub in found_subs:
            self.log("OSINT", f"  -> Subdomain: {sub['subdomain']} ({sub['ip']})", "green")
        self.emit("tool_result", {"tool": "subdomain_enumerate", "data": subdomain_data})
        if self.aborted(): return {}

        # ── Certificate Transparency (NEW) ────────────────────────────────────
        self.log("TOOL", f"cert_transparency_recon({target})", "dim")
        self.log("OSINT", "  -> Querying crt.sh certificate logs (passive)...", "")
        try:
            ct_data = await asyncio.to_thread(cert_transparency_recon, target, self.validator)
            ct_live = ct_data.get("live_count", 0)
            ct_interesting = len(ct_data.get("interesting_subdomains", []))
            self.log("OSINT", f"  -> CT found {ct_data.get('total_unique', 0)} unique subdomains ({ct_live} live, {ct_interesting} interesting)", "green")
            for sub in ct_data.get("interesting_subdomains", []):
                self.log("OSINT", f"  -> [CT] Interesting: {sub['subdomain']} ({sub.get('ip', 'unresolved')})", "red")
            self.emit("tool_result", {"tool": "cert_transparency", "data": ct_data})
        except Exception as e:
            self.log("WARN", f"CT recon failed: {e}", "orange")
            ct_data = {}
        if self.aborted(): return {}

        # HTTP probe
        self.log("TOOL", f"http_probe(https://{target})", "dim")
        http_data = await asyncio.to_thread(http_probe, f"https://{target}", self.validator)
        if http_data.get("error"):
            self.log("WARN", f"  -> http_probe error: {http_data['error']}", "orange")
            if not http_data.get("tech_signals") and not http_data.get("status_code"):
                self.log(
                    "WARN",
                    "  -> http_probe returned no usable data — target may only be reachable on a port unavailable from this host. Recon phases will have limited coverage.",
                    "orange",
                )
        for tech in http_data.get("tech_signals", []):
            self.log("OSINT", f"  -> Tech detected: {tech}", "green")
        if http_data.get("cpe_strings"):
            self.log("OSINT", f"  -> CPE strings: {http_data['cpe_strings']}", "green")
        self.emit("tool_result", {"tool": "http_probe", "data": http_data})
        if self.aborted(): return {}

        # ── JS Intelligence (NEW) ─────────────────────────────────────────────
        js_seed_url = http_data.get("url") or f"https://{target}"
        self.log("TOOL", f"js_intelligence({js_seed_url})", "dim")
        self.log("OSINT", "  -> Extracting endpoints/secrets from JavaScript...", "")
        try:
            js_data = await asyncio.to_thread(
                js_intelligence,
                js_seed_url,
                self.validator,
                seed_html=http_data.get("body_preview", ""),
                fallback_urls=http_data.get("candidate_urls", []),
            )
            ep_count = len(js_data.get("endpoints", []))
            sec_count = len(js_data.get("secrets", []))
            page_count = len(js_data.get("pages_crawled", []))
            form_count = js_data.get("form_count", 0)
            self.log(
                "OSINT",
                f"  -> JS: {ep_count} endpoints, {sec_count} secrets, {js_data.get('script_count', 0)} scripts analyzed, "
                f"{page_count} pages crawled, {form_count} forms",
                "green",
            )
            for page in js_data.get("pages_crawled", [])[:5]:
                self.log("OSINT", f"  -> [CRAWL] {page['url']} ({page['routes']} routes, {page['forms']} forms)", "dim")
            for secret in js_data.get("secrets", []):
                self.log("OSINT", f"  -> [JS SECRET] {secret['type']}: {secret['value_preview']} [{secret['severity']}]", "red")
            for host in js_data.get("internal_hosts", []):
                self.log("OSINT", f"  -> [JS INTERNAL] {host}", "orange")
            for ep in js_data.get("endpoints", [])[:5]:
                self.log("OSINT", f"  -> [JS API] {ep}", "dim")
            self.emit("tool_result", {"tool": "js_intelligence", "data": js_data})
        except Exception as e:
            self.log("WARN", f"JS intelligence failed: {e}", "orange")
            js_data = {}
        if self.aborted(): return {}

        # Misconfigs
        misconfig_seed_url = http_data.get("url") or f"https://{target}"
        self.log("TOOL", f"check_common_misconfigs({misconfig_seed_url})", "dim")
        self.log("OSINT", "  -> Checking common exposed paths (time-bounded scan)...", "")
        misconfig_data = await asyncio.to_thread(
            check_common_misconfigs, misconfig_seed_url, self.validator
        )
        if misconfig_data.get("budget_exhausted"):
            self.log(
                "WARN",
                f"  -> Misconfig scan hit time budget after {misconfig_data.get('paths_checked', 0)}/"
                f"{misconfig_data.get('paths_total', 0)} paths",
                "orange",
            )
        for finding in misconfig_data.get("findings", []):
            color = "red" if finding["severity"] == "HIGH" else "orange"
            self.log("OSINT", f"  -> Exposed: {finding['path']} [{finding['severity']}]", color)
        self.emit("tool_result", {"tool": "misconfigs", "data": misconfig_data})

        # AI synthesis
        self.log("OSINT", "Synthesizing intelligence with AI...", "")
        osint_report = await self._ai_synthesize_osint(
            target, dns_data, whois_data, subdomain_data, http_data, misconfig_data, ct_data, js_data
        )

        # Attach raw data for downstream phases
        osint_report["_cpe_strings"] = http_data.get("cpe_strings", [])
        osint_report["_tech_details"] = http_data.get("tech_details", [])
        osint_report["_ct_data"] = ct_data
        osint_report["_ct_subdomains"] = ct_data.get("live_subdomains", [])
        osint_report["_js_data"] = js_data
        osint_report["_js_endpoints_count"] = len(js_data.get("endpoints", []))
        osint_report["_misconfigs"] = misconfig_data.get("findings", [])
        osint_report["_missing_security_headers"] = http_data.get("missing_security_headers", [])

        total_subs = len(found_subs) + ct_data.get("live_count", 0)
        self.log("SUCCESS",
            f"OSINT complete — {total_subs} subdomains, {len(js_data.get('endpoints', []))} JS endpoints, "
            f"risk score: {osint_report.get('risk_score', '?')}/10", "green")
        return osint_report

    async def _ai_synthesize_osint(self, target, dns, whois, subdomains, http, misconfigs, ct_data, js_data) -> dict:
        ct_interesting = [s["subdomain"] for s in ct_data.get("interesting_subdomains", [])]
        raw_data = {
            "dns": dns.get("records", {}),
            "resolved_ip": dns.get("resolved_ip", ""),
            "whois": whois.get("fields", {}),
            "subdomains_brute": [s["subdomain"] for s in subdomains.get("discovered_subdomains", [])],
            "ct_interesting_subdomains": ct_interesting,
            "ct_total_found": ct_data.get("total_unique", 0),
            "server_header": http.get("server_header", ""),
            "powered_by_header": http.get("powered_by_header", ""),
            "tech_signals": http.get("tech_signals", []),
            "cpe_strings": http.get("cpe_strings", []),
            "js_endpoints_found": len(js_data.get("endpoints", [])),
            "js_secrets_found": len(js_data.get("secrets", [])),
            "js_internal_hosts": js_data.get("internal_hosts", []),
            "js_cloud_resources": [r["value"] for r in js_data.get("cloud_resources", [])],
            "missing_security_headers": http.get("missing_security_headers", []),
            "misconfigs_found": misconfigs.get("findings", []),
            "http_status": http.get("status_code"),
        }

        prompt = f"""Analyze this OSINT data for {target} and return a structured intelligence report.

RAW DATA:
{json.dumps(raw_data, indent=2)}

Return ONLY valid JSON — no markdown, no preamble:
{{
  "summary": "2-3 sentence executive summary including CT findings and JS intelligence",
  "infrastructure": {{
    "hosting": "Use 'Unknown' unless directly supported by the provided evidence",
    "cdn": null,
    "org": "Registrant organization from whois or null"
  }},
  "subdomains": {json.dumps(subdomains.get("discovered_subdomains", [])[:10])},
  "technology_stack": ["copy only directly observed technologies with version"],
  "open_ports": [],
  "risk_score": 5,
  "misconfig_count": {len(misconfigs.get("findings", []))},
  "attack_surface_notes": "use only provided evidence; never infer unseen providers, products, or ports"
}}"""

        try:
            response = client.messages.create(
                model=DEFAULT_MODEL,
                max_tokens=900,
                messages=[{"role": "user", "content": prompt}],
                response_format="json",
                max_retries=2,
            )
            text = response.content[0].text
            cleaned = _clean_json(text)
            if not cleaned:
                raise ValueError(f"No JSON in response. Raw: {text[:300]!r}")
            return _ground_osint_report(target, dns, whois, subdomains, http, misconfigs, ct_data, js_data, json.loads(cleaned))
        except Exception as ex:
            self.log("WARN", f"AI synthesis failed: {ex}", "orange")

        return _ground_osint_report(target, dns, whois, subdomains, http, misconfigs, ct_data, js_data, {})

    # ── Recon Phase ───────────────────────────────────────────────────────────
    async def _run_recon(self, osint_data: dict) -> dict:
        target = self.target
        self.log("RECON", "Initializing CVE & vulnerability hunter", "")
        await asyncio.sleep(0.1)

        # Port scan
        self.log("TOOL", f"port_scan({target}, common ports)", "dim")
        try:
            port_data = await asyncio.to_thread(
                port_scan, target,
                "21,22,23,25,80,443,3000,3306,5432,6379,8080,8443,9200,27017",
                self.validator
            )
            for p in port_data.get("open_ports", []):
                self.log("RECON", f"  -> {p}", "orange")
            self.emit("tool_result", {"tool": "port_scan", "data": port_data})
        except Exception as e:
            self.log("WARN", f"Port scan failed: {e}", "orange")
            port_data = {"open_ports": []}
        if self.aborted(): return {}

        # CVE lookups
        cve_results = []
        cpe_strings = list(osint_data.get("_cpe_strings", []))
        tech_stack = list(osint_data.get("technology_stack", []))
        port_cpes = [
            t["cpe"] for t in port_data.get("detected_tech", [])
            if isinstance(t, dict) and t.get("cpe")
        ]
        if port_cpes:
            for cpe in port_cpes:
                if cpe not in cpe_strings:
                    cpe_strings.append(cpe)
            detected_names = [t.get("name") for t in port_data.get("detected_tech", []) if t.get("name")]
            for name in detected_names:
                if name not in tech_stack:
                    tech_stack.append(name)
            osint_data["technology_stack"] = tech_stack
            self.log("RECON", f"  -> Reusing {len(port_cpes)} service fingerprints from port scan", "orange")

        skip_cve_lookup = not cpe_strings and not tech_stack
        if skip_cve_lookup:
            self.log(
                "WARN",
                "Skipping CVE lookups due to no detected technology after service enumeration. This indicates limited collection visibility, not an absence of vulnerabilities.",
                "orange",
            )

        if cpe_strings:
            self.log("RECON", f"CVE lookups for {len(cpe_strings)} detected components...", "")
            for cpe in cpe_strings[:4]:
                self.log("TOOL", f"fetch_cve_data({cpe})", "dim")
                try:
                    cves = await asyncio.to_thread(fetch_cve_data, cpe)
                    total = cves.get("total", 0)
                    if total > 0:
                        self.log("RECON", f"  -> {total} CVEs found for {cpe}", "orange")
                    cve_results.extend(cves.get("vulnerabilities", [])[:4])
                    self.emit("tool_result", {"tool": "cve_lookup", "cpe": cpe, "data": cves})
                except Exception as e:
                    self.log("WARN", f"CVE lookup failed for {cpe}: {e}", "orange")
                if self.aborted(): return {}
                await asyncio.sleep(0.6)
        elif tech_stack:
            for tech in osint_data.get("technology_stack", [])[:3]:
                cpe = tech.lower().replace(" ", ":").replace("/", ":")
                self.log("TOOL", f"fetch_cve_data({cpe}) [keyword]", "dim")
                try:
                    cves = await asyncio.to_thread(fetch_cve_data, cpe)
                    if cves.get("total", 0) > 0:
                        self.log("RECON", f"  -> {cves['total']} CVEs for {tech}", "orange")
                    cve_results.extend(cves.get("vulnerabilities", [])[:4])
                    self.emit("tool_result", {"tool": "cve_lookup", "tech": tech, "data": cves})
                except Exception as e:
                    self.log("WARN", f"CVE lookup failed for {tech}: {e}", "orange")
                if self.aborted(): return {}
                await asyncio.sleep(0.6)

        cve_results = _dedupe_cves(cve_results)

        # ── EPSS Scoring (NEW) ────────────────────────────────────────────────
        if cve_results:
            self.log("TOOL", f"epss_scoring({len(cve_results)} CVEs)", "dim")
            self.log("RECON", "  -> Fetching exploitation probability scores...", "")
            try:
                cve_results = await asyncio.to_thread(enrich_cves_with_epss, cve_results)
                epss_sum = epss_summary(cve_results)
                p1 = epss_sum.get("p1_immediate", 0)
                high_risk = epss_sum.get("high_exploitation_risk", 0)
                if p1 > 0:
                    self.log("RECON", f"  -> EPSS: {p1} P1-IMMEDIATE CVEs, {high_risk} with >10% exploit probability", "red")
                else:
                    self.log("RECON", f"  -> EPSS: {high_risk} CVEs with elevated exploit probability", "orange")
                for cve in cve_results[:3]:
                    if cve.get("epss", 0) > 0.01:
                        self.log("RECON", f"  -> {cve['id']}: EPSS {cve['epss_percent']}% — {cve.get('priority', '')}", "orange")
                self.emit("tool_result", {"tool": "epss_scoring", "data": {"cves": cve_results, "summary": epss_sum}})
            except Exception as e:
                self.log("WARN", f"EPSS scoring failed: {e}", "orange")
                epss_sum = {}
        else:
            epss_sum = {}

        # AI vulnerability analysis
        self.log("RECON", "Analyzing vulnerabilities with AI...", "")
        vuln_report = await self._ai_vuln_analysis(target, osint_data, port_data, cve_results)

        # Tag with MITRE and attach EPSS summary
        vuln_report["high_findings"] = map_to_mitre(vuln_report.get("high_findings", []))
        vuln_report["critical_findings"] = map_to_mitre(vuln_report.get("critical_findings", []))
        vuln_report["medium_findings"] = map_to_mitre(vuln_report.get("medium_findings", []))
        vuln_report["cve_matches"] = cve_results
        vuln_report["_epss_summary"] = epss_sum
        vuln_report["_open_ports"] = port_data.get("open_ports", [])
        vuln_report["_service_fingerprints"] = port_data.get("detected_tech", [])

        total = (len(vuln_report.get("critical_findings", [])) +
                 len(vuln_report.get("high_findings", [])) +
                 len(vuln_report.get("medium_findings", [])))
        self.log("SUCCESS", f"Recon complete — {total} findings, {len(cve_results)} CVEs, "
                 f"{epss_sum.get('p1_immediate', 0)} P1-immediate", "green")
        return vuln_report

    async def _ai_vuln_analysis(self, target, osint, ports, cves) -> dict:
        js_data = osint.get("_js_data", {})
        prompt = f"""Analyze this data for {target} and produce a vulnerability assessment.

TECH STACK: {osint.get("technology_stack", [])}
CPE STRINGS: {osint.get("_cpe_strings", [])}
MISCONFIGS: {osint.get("misconfig_count", 0)} found
OPEN PORTS: {ports.get("open_ports", [])}
JS ENDPOINTS FOUND: {osint.get("_js_endpoints_count", 0)}
JS SECRETS FOUND: {len(js_data.get("secrets", []))}
JS INTERNAL HOSTS: {js_data.get("internal_hosts", [])}
CVE MATCHES (with EPSS scores):
{json.dumps([{
    "id": c.get("id"), "cvss": c.get("cvss_score"),
    "epss_percent": c.get("epss_percent", 0),
    "priority": c.get("priority", ""),
    "description": c.get("description", "")[:100]
} for c in cves[:8]], indent=2)}

Return ONLY valid JSON — no markdown:
{{
  "critical_findings": [{{"title": "...", "description": "...", "cvss_score": 9.0, "affected": "..."}}],
  "high_findings": [{{"title": "...", "description": "...", "cvss_score": 7.5, "affected": "..."}}],
  "medium_findings": [{{"title": "...", "description": "...", "cvss_score": 5.0, "affected": "..."}}],
  "attack_vectors": ["list attack vectors"],
  "scan_summary": "include EPSS context — which CVEs are actively exploited"
}}

Use only provided evidence. Do not invent products, versions, open ports, or recommendations not present in the input. Include JS secrets as critical findings if present. Reference EPSS scores in your analysis."""

        try:
            response = client.messages.create(
                model=DEFAULT_MODEL,
                max_tokens=1200,
                messages=[{"role": "user", "content": prompt}],
                response_format="json",
                max_retries=2,
            )
            text = response.content[0].text
            cleaned = _clean_json(text)
            if not cleaned:
                raise ValueError(f"No JSON in response. Raw: {text[:300]!r}")
            return _ground_vuln_report(target, osint, ports, cves, json.loads(cleaned))
        except Exception as ex:
            self.log("WARN", f"AI vuln analysis failed: {ex}", "orange")

        return _ground_vuln_report(target, osint, ports, cves, {})

    # ── Red Team Phase ────────────────────────────────────────────────────────
    async def _run_redteam(self, vuln_data: dict, osint_data: dict) -> dict:
        target = self.target
        self.log("REDTEAM", "Initializing red team agent — authorized scope only", "red")
        await asyncio.sleep(0.1)

        test_results = []
        findings_to_test = list(vuln_data.get("critical_findings", [])) + list(vuln_data.get("high_findings", []))
        for finding in vuln_data.get("medium_findings", []):
            title = finding.get("title", "").lower()
            if any(marker in title for marker in ["missing security headers", "cors", "exposed path"]):
                findings_to_test.append(finding)
        findings_to_test = findings_to_test[:3]

        for finding in findings_to_test:
            if self.aborted(): break
            name = finding.get("title", "Unknown")
            self.log("TOOL", f"test_vulnerability({name[:50]})", "dim")
            await asyncio.sleep(0.8)
            try:
                if "exposed path" in name.lower():
                    result = await asyncio.to_thread(
                        _test_exposed_path, f"https://{target}", finding, self.validator
                    )
                    test_results.append({"test": "exposed_path", "finding": name, "result": result})
                    self.emit("tool_result", {"tool": "exposed_path_test", "data": result})
                elif any(kw in name.lower() for kw in ["cred", "auth", "admin", "login"]):
                    result = await asyncio.to_thread(
                        _test_default_creds, f"https://{target}", self.validator
                    )
                    test_results.append({"test": "default_credentials", "finding": name, "result": result})
                    self.emit("tool_result", {"tool": "default_creds", "data": result})
                elif "cors" in name.lower():
                    result = await asyncio.to_thread(
                        _test_cors, f"https://{target}", self.validator
                    )
                    test_results.append({"test": "cors", "finding": name, "result": result})
                    self.emit("tool_result", {"tool": "cors_test", "data": result})
                elif "missing security headers" in name.lower():
                    result = await asyncio.to_thread(
                        _test_missing_security_headers, f"https://{target}", finding, self.validator
                    )
                    test_results.append({"test": "missing_security_headers", "finding": name, "result": result})
                    self.emit("tool_result", {"tool": "missing_header_test", "data": result})
                else:
                    self.log("REDTEAM", f"  -> Passive check: {name[:50]}", "")
                    await asyncio.sleep(0.5)
                    test_results.append({
                        "test": name, "finding": name, "result": {"status": "checked", "manual_verification_needed": True}
                    })
            except Exception as e:
                self.log("WARN", f"  -> Test error: {e}", "orange")

        # ── Attack Graph + Kill Chains (NEW) ──────────────────────────────────
        self.log("REDTEAM", "Building attack graph...", "red")
        try:
            graph = await asyncio.to_thread(
                build_attack_graph,
                target,
                osint_data,
                vuln_data,
                osint_data.get("_ct_data", {}),
                osint_data.get("_js_data", {})
            )
            self.log("REDTEAM", f"  -> Graph: {len(graph.nodes)} nodes, {len(graph.get_critical_paths())} critical paths", "red")

            self.log("REDTEAM", "Generating kill chains with AI...", "red")
            kill_chain_data = await asyncio.to_thread(generate_kill_chains, graph, client, DEFAULT_MODEL)

            chains = kill_chain_data.get("kill_chains", [])
            for chain in chains:
                self.log("REDTEAM", f"  -> Kill chain: {chain.get('name')} [{chain.get('likelihood')}]", "red")

            self.emit("tool_result", {"tool": "attack_graph", "data": {
                "graph_summary": graph.to_dict(),
                "kill_chains": kill_chain_data
            }})
        except Exception as e:
            self.log("WARN", f"Attack graph failed: {e}", "orange")
            kill_chain_data = {"kill_chains": [], "worst_case_scenario": "", "overall_chain_risk": "UNKNOWN"}
            graph = None

        self.log("REDTEAM", "Synthesizing red team report...", "")
        redteam_report = await self._ai_redteam_synthesis(target, vuln_data, test_results, kill_chain_data)
        self.log("SUCCESS", f"Red team complete — risk: {redteam_report.get('overall_risk')}, "
                 f"{len(redteam_report.get('kill_chains', []))} kill chains", "green")
        return redteam_report

    async def _ai_redteam_synthesis(self, target, vulns, test_results, kill_chain_data) -> dict:
        cve_matches = vulns.get("cve_matches", [])
        all_findings = vulns.get("critical_findings", []) + vulns.get("high_findings", [])
        max_cvss = max((c.get("cvss_score") or 0 for c in cve_matches), default=0)
        max_epss = max((c.get("epss", 0) for c in cve_matches), default=0)
        has_eol = any("5.6" in str(t) or "end-of-life" in str(t).lower()
                      for t in vulns.get("attack_vectors", []) + [vulns.get("scan_summary", "")])

        if max_cvss >= 9.0 or vulns.get("critical_findings"):
            risk_floor = "CRITICAL"
        elif max_cvss >= 7.0 or vulns.get("high_findings") or has_eol:
            risk_floor = "HIGH"
        elif max_cvss >= 4.0:
            risk_floor = "MEDIUM"
        else:
            risk_floor = "LOW"

        prompt = f"""Produce a final red team assessment for {target}.

RISK FLOOR: {risk_floor} (do not rate lower than this)
MAX CVE CVSS: {max_cvss} | MAX EPSS: {max_epss*100:.1f}%
KILL CHAINS IDENTIFIED: {len(kill_chain_data.get("kill_chains", []))}
WORST CASE: {kill_chain_data.get("worst_case_scenario", "N/A")}

VULNERABILITIES:
{json.dumps(all_findings[:5], indent=2)}

CVEs (with EPSS):
{json.dumps([{"id": c.get("id"), "cvss": c.get("cvss_score"), "epss_pct": c.get("epss_percent", 0), "priority": c.get("priority", "")} for c in cve_matches[:5]], indent=2)}

TEST RESULTS: {json.dumps(test_results, indent=2)}

Rules:
- overall_risk must be >= {risk_floor}
- Reference EPSS scores and kill chains in summary
- Only recommend actions directly supported by provided evidence; never invent unseen products or version numbers

Return ONLY valid JSON:
{{
  "confirmed_vulnerabilities": [],
  "kill_chains": {json.dumps(kill_chain_data.get("kill_chains", []))},
  "proof_of_concepts": [],
  "overall_risk": "{risk_floor}",
  "engagement_summary": "paragraph covering CVEs, EPSS scores, kill chains, and business risk",
  "recommendations": [
    {{"priority": "CRITICAL", "recommendation": "specific fix with version"}},
    {{"priority": "HIGH", "recommendation": "specific fix"}},
    {{"priority": "HIGH", "recommendation": "specific fix"}},
    {{"priority": "MEDIUM", "recommendation": "specific fix"}}
  ]
}}"""

        try:
            response = client.messages.create(
                model=DEFAULT_MODEL,
                max_tokens=1500,
                messages=[{"role": "user", "content": prompt}],
                response_format="json",
                max_retries=2,
            )
            text = response.content[0].text
            cleaned = _clean_json(text)
            if not cleaned:
                raise ValueError(f"No JSON in response. Raw: {text[:300]!r}")
            result = json.loads(cleaned)
            if isinstance(result, list):
                result = {
                    "confirmed_vulnerabilities": [],
                    "kill_chains": result,
                    "proof_of_concepts": [],
                    "overall_risk": risk_floor,
                    "engagement_summary": "",
                    "recommendations": [],
                }
            if not isinstance(result, dict):
                raise ValueError(f"Unexpected red team response shape: {type(result).__name__}")

            # Enforce risk floor
            risk_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            ai_risk = result.get("overall_risk", "LOW").upper()
            if risk_order.index(ai_risk) < risk_order.index(risk_floor):
                self.log("WARN", f"AI rated {ai_risk}, overriding to floor {risk_floor}", "orange")
                result["overall_risk"] = risk_floor

            # Always attach kill chains even if AI response didn't include them
            if not result.get("kill_chains"):
                result["kill_chains"] = kill_chain_data.get("kill_chains", [])

            return _ground_redteam_report(target, vulns, test_results, kill_chain_data, result)
        except Exception as ex:
            self.log("WARN", f"AI red team synthesis failed: {ex}", "orange")

        return _ground_redteam_report(target, vulns, test_results, kill_chain_data, {})


# ── Test helpers ──────────────────────────────────────────────────────────────
def _test_default_creds(url: str, scope: ScopeValidator) -> dict:
    import urllib.request, ssl
    scope.assert_in_scope(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    found = []
    for path in ["/admin", "/admin/login", "/login", "/wp-admin"]:
        try:
            req = urllib.request.Request(url.rstrip("/") + path, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
                if resp.status == 200:
                    found.append(path)
        except Exception:
            pass
    return {"accessible_panels": found, "default_creds_required_manual_test": True}


def _test_cors(url: str, scope: ScopeValidator) -> dict:
    import urllib.request, ssl
    scope.assert_in_scope(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={
            "Origin": "https://evil.example.com", "User-Agent": "Mozilla/5.0"
        })
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            return {"acao": acao, "misconfigured": acao in ["*", "https://evil.example.com"]}
    except Exception as e:
        return {"error": str(e)}


def _request_headers(url: str, scope: ScopeValidator, method: str = "HEAD", extra_headers: dict | None = None) -> dict:
    import ssl
    import urllib.error
    import urllib.request

    scope.assert_in_scope(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {"User-Agent": "Mozilla/5.0"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            return {"url": url, "status_code": resp.status, "headers": dict(resp.headers)}
    except urllib.error.HTTPError as exc:
        return {"url": url, "status_code": exc.code, "headers": dict(exc.headers or {}), "error": str(exc)}
    except Exception as exc:
        return {"url": url, "error": str(exc), "headers": {}}


def _test_exposed_path(base_url: str, finding: dict, scope: ScopeValidator) -> dict:
    import urllib.parse

    raw_path = str(finding.get("affected") or "").strip()
    if not raw_path:
        m = re.search(r"exposed path\s+(.+)$", finding.get("title", ""), re.IGNORECASE)
        raw_path = m.group(1).strip() if m else ""
    if not raw_path:
        return {"error": "no path to verify", "confirmed": False}

    if raw_path.startswith("http://") or raw_path.startswith("https://"):
        full_url = raw_path
        path = urllib.parse.urlparse(raw_path).path or "/"
    else:
        path = raw_path if raw_path.startswith("/") else f"/{raw_path}"
        full_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

    result = _request_headers(full_url, scope, method="HEAD")
    if result.get("status_code") == 405 or not result.get("status_code"):
        result = _request_headers(full_url, scope, method="GET")

    status = result.get("status_code", 0) or 0
    confirmed = status in {200, 401, 403}
    return {
        "path": path,
        "url": full_url,
        "status_code": status,
        "confirmed": confirmed,
        "manual_verification_needed": not confirmed,
        "error": result.get("error", ""),
    }


def _test_missing_security_headers(base_url: str, finding: dict, scope: ScopeValidator) -> dict:
    expected = []
    desc = str(finding.get("description", ""))
    if ":" in desc:
        expected = [h.strip() for h in desc.split(":", 1)[1].split(",") if h.strip()]
    if not expected:
        expected = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]

    result = _request_headers(base_url, scope, method="HEAD")
    if result.get("status_code") == 405 or not result.get("status_code"):
        result = _request_headers(base_url, scope, method="GET")

    headers = result.get("headers", {})
    missing = [header for header in expected if not headers.get(header)]
    return {
        "url": base_url,
        "status_code": result.get("status_code", 0) or 0,
        "missing_headers_confirmed": missing,
        "confirmed": bool(missing),
        "error": result.get("error", ""),
    }
