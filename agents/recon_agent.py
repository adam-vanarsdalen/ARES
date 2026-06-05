"""
ARES — Recon Agent
Autonomous CVE and misconfiguration hunter.
Takes OSINT intelligence as input and hunts for specific vulnerabilities.
"""

import json
from ollama_compat import OllamaClient as Anthropic, DEFAULT_MODEL, ollama_chat
from utils.config import OLLAMA_MAX_RETRIES, OLLAMA_TIMEOUT
from utils.scope_validator import ScopeValidator, Scope
from tools.network_tools import (
    port_scan, http_probe, fetch_cve_data, check_common_misconfigs
)

client = Anthropic()
OLLAMA_TIMEOUT_S = OLLAMA_TIMEOUT

RECON_SYSTEM_PROMPT = """You are ARES-RECON, an autonomous vulnerability reconnaissance agent.

You receive OSINT intelligence from a previous phase and your job is to:
1. Identify specific software versions and services running on discovered hosts
2. Query CVE databases for known vulnerabilities in those versions
3. Check for common misconfigurations across all discovered services
4. Port scan discovered hosts to find additional exposed services
5. Prioritize findings by severity (CVSS score and exploitability)

You think like a methodical security reviewer:
- Prefer verification notes over exploitation.
- Do not provide exploit steps, payloads, or instructions.
- Do not invent technologies, versions, or vulnerabilities.
- Every finding must cite evidence_ids from tool outputs.

IMPORTANT: ONLY operate against targets explicitly in scope.

Output the FINAL report ONLY via the compile_vuln_report tool.
The report must be valid JSON matching this shape (no extra keys):
{
  "status": "ok|partial|error",
  "errors": ["..."],
  "critical_findings": [{"title":"...","description":"...","cvss_score":9.0,"affected":"...","confidence":"low|medium|high","evidence_ids":["..."],"hypothesis":false}],
  "high_findings": [...],
  "medium_findings": [...],
  "cve_matches": [{"id":"CVE-...","description":"...","cvss_score":7.5,"severity":"HIGH","published":"YYYY-MM-DD","confidence":"low|medium|high","evidence_ids":["..."]}],
  "attack_vectors": ["..."],
  "scan_summary": "..."
}"""

RECON_TOOLS = [
    {
        "name": "port_scan",
        "description": "Run nmap port scan to discover open ports and service versions",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP or hostname to scan"},
                "ports": {"type": "string", "description": "Port range e.g. '80,443,22,8080-8090' or '1-1000'"}
            },
            "required": ["target", "ports"]
        }
    },
    {
        "name": "fetch_cve_data",
        "description": "Query NVD database for CVEs matching a software/version. Use CPE format like 'apache:http_server:2.4.49'",
        "input_schema": {
            "type": "object",
            "properties": {
                "cpe_string": {"type": "string", "description": "CPE identifier e.g. 'nginx:nginx:1.18.0'"}
            },
            "required": ["cpe_string"]
        }
    },
    {
        "name": "http_probe",
        "description": "Probe HTTP endpoint for headers, tech stack, and security posture",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to probe"}
            },
            "required": ["url"]
        }
    },
    {
        "name": "check_common_misconfigs",
        "description": "Check for exposed sensitive files and misconfigurations",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL to check"}
            },
            "required": ["url"]
        }
    },
    {
        "name": "compile_vuln_report",
        "description": "Compile all vulnerability findings into final report. Call when assessment is complete.",
        "input_schema": {
            "type": "object",
            "properties": {
                "report": {
                    "type": "object",
                    "description": "Complete vulnerability assessment report"
                }
            },
            "required": ["report"]
        }
    }
]


def execute_tool(tool_name: str, tool_input: dict, scope: ScopeValidator) -> str:
    try:
        if tool_name == "port_scan":
            result = port_scan(tool_input["target"], tool_input["ports"], scope)
        elif tool_name == "fetch_cve_data":
            result = fetch_cve_data(tool_input["cpe_string"])
        elif tool_name == "http_probe":
            result = http_probe(tool_input["url"], scope)
        elif tool_name == "check_common_misconfigs":
            result = check_common_misconfigs(tool_input["url"], scope)
        elif tool_name == "compile_vuln_report":
            return json.dumps({"status": "report_compiled", "report": tool_input["report"]})
        else:
            result = {"error": f"Unknown tool: {tool_name}"}
        return json.dumps(result)
    except ValueError as e:
        return json.dumps({"error": str(e), "blocked": True})
    except Exception as e:
        return json.dumps({"error": f"Tool execution failed: {str(e)}"})


class ReconAgent:
    def __init__(self, scope: Scope, verbose: bool = True):
        self.scope = scope
        self.validator = ScopeValidator(scope)
        self.verbose = verbose
        self.final_report = None

    def log(self, msg: str):
        if self.verbose:
            print(f"[RECON] {msg}")

    def run(self, osint_report: dict) -> dict:
        """
        Run vulnerability recon using OSINT report as input.
        osint_report: output from OSINTAgent.run()
        """
        self.log("Starting CVE & vulnerability reconnaissance")

        prompt = f"""Analyze this OSINT intelligence report and perform vulnerability reconnaissance.

OSINT REPORT:
{json.dumps(osint_report, indent=2)}

Systematically:
1. Port scan all discovered hosts and subdomains
2. For each identified service/technology, search for CVEs
3. Check all web services for misconfigurations
4. Prioritize findings and identify attack chains
5. Compile a final vulnerability assessment"""

        messages = [{"role": "user", "content": prompt}]
        max_iterations = 25
        iteration = 0

        while iteration < max_iterations:
            iteration += 1
            self.log(f"Hunting vulnerabilities... (iteration {iteration})")

            response = client.messages.create(
                model=DEFAULT_MODEL,
                max_tokens=4096,
                system=RECON_SYSTEM_PROMPT,
                tools=RECON_TOOLS,
                messages=messages,
                timeout_s=OLLAMA_TIMEOUT_S,
                max_retries=OLLAMA_MAX_RETRIES,
            )

            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                self.log("Recon complete")
                break

            if response.stop_reason == "tool_use":
                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        self.log(f"Tool: {block.name}")
                        result = execute_tool(block.name, block.input, self.validator)

                        parsed = json.loads(result)
                        if parsed.get("status") == "report_compiled":
                            report_obj = parsed.get("report") or {}
                            if isinstance(report_obj, dict):
                                self.final_report = report_obj
                            else:
                                self.final_report = {
                                    "status": "partial",
                                    "errors": ["invalid_report"],
                                    "scan_summary": "Recon report was not a JSON object.",
                                }

                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result
                        })

                messages.append({"role": "user", "content": tool_results})

        return self.final_report or {
            "status": "partial",
            "errors": ["no_final_report"],
            "scan_summary": "Recon agent ended without a final report.",
        }
