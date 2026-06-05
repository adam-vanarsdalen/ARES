"""
ARES — OSINT Agent
An Ollama-powered agent that autonomously gathers open-source intelligence
on a target, deciding which tools to use and in what order.
"""

import json
from ollama_compat import OllamaClient as Anthropic, DEFAULT_MODEL, ollama_chat
from utils.config import OLLAMA_MAX_RETRIES, OLLAMA_TIMEOUT
from utils.scope_validator import ScopeValidator, Scope
from tools.network_tools import (
    dns_lookup, whois_lookup, subdomain_enumerate,
    http_probe, check_common_misconfigs
)

client = Anthropic()
OLLAMA_TIMEOUT_S = OLLAMA_TIMEOUT

# Common subdomain wordlist — expand this significantly in production
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "test", "portal", "admin",
    "beta", "app", "cloud", "cdn", "git", "jenkins", "jira", "confluence",
    "gitlab", "grafana", "kibana", "monitor", "status", "docs", "help", "support"
]

OSINT_SYSTEM_PROMPT = """You are ARES-OSINT, an autonomous open-source intelligence agent.

Your mission: Given a target domain or organization, systematically gather intelligence
using available tools to build a comprehensive picture of the attack surface.

You operate methodically:
1. Start broad (DNS, WHOIS) to understand the infrastructure
2. Enumerate subdomains to expand the surface
3. Probe live services for technology fingerprinting
4. Check for misconfigurations and exposed sensitive paths
5. Correlate findings into a structured intelligence report

IMPORTANT: You ONLY operate against targets explicitly in scope. Never attempt to access
systems outside defined scope.

Be thorough but efficient. After each tool call, analyze results and decide next steps.
When you have enough intelligence, compile a final structured report.

Output the FINAL report ONLY via the compile_final_report tool.
The report must be valid JSON matching this shape (no extra keys):
{
  "status": "ok|partial|error",
  "errors": ["..."],
  "summary": "executive summary",
  "infrastructure": {"hosting": "...", "cdn": null, "org": null},
  "subdomains": [{"subdomain":"...","ip":"..."}],
  "technology_stack": ["..."],
  "open_ports": ["80","443"],
  "risk_score": 0,
  "misconfig_count": 0,
  "attack_surface_notes": "...",
  "evidence": [{"evidence_id":"...","source":"dns|whois|subdomains|http_probe|misconfigs|other","summary":"..."}]
}"""


# Tool definitions for Claude
OSINT_TOOLS = [
    {
        "name": "dns_lookup",
        "description": "Resolve DNS records (A, MX, NS, TXT, CNAME) for a domain to map infrastructure",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to look up"}
            },
            "required": ["domain"]
        }
    },
    {
        "name": "whois_lookup",
        "description": "Get WHOIS registration data — registrar, dates, nameservers, org info",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to look up"}
            },
            "required": ["domain"]
        }
    },
    {
        "name": "subdomain_enumerate",
        "description": "Brute-force enumerate subdomains using wordlist",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Root domain to enumerate"}
            },
            "required": ["domain"]
        }
    },
    {
        "name": "http_probe",
        "description": "Probe HTTP/HTTPS endpoint — status, headers, tech stack, security headers audit",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to probe (include https://)"}
            },
            "required": ["url"]
        }
    },
    {
        "name": "check_common_misconfigs",
        "description": "Check for exposed sensitive files and common misconfigurations (.env, .git, admin panels, API docs)",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL to check"}
            },
            "required": ["url"]
        }
    },
    {
        "name": "compile_final_report",
        "description": "Compile all gathered intelligence into final structured report. Call this when reconnaissance is complete.",
        "input_schema": {
            "type": "object",
            "properties": {
                "report": {
                    "type": "object",
                    "description": "The complete intelligence report as structured JSON"
                }
            },
            "required": ["report"]
        }
    }
]


def execute_tool(tool_name: str, tool_input: dict, scope: ScopeValidator) -> str:
    """Execute a tool call and return result as string."""
    try:
        if tool_name == "dns_lookup":
            result = dns_lookup(tool_input["domain"], scope)
        elif tool_name == "whois_lookup":
            result = whois_lookup(tool_input["domain"], scope)
        elif tool_name == "subdomain_enumerate":
            result = subdomain_enumerate(tool_input["domain"], SUBDOMAIN_WORDLIST, scope)
        elif tool_name == "http_probe":
            result = http_probe(tool_input["url"], scope)
        elif tool_name == "check_common_misconfigs":
            result = check_common_misconfigs(tool_input["url"], scope)
        elif tool_name == "compile_final_report":
            return json.dumps({"status": "report_compiled", "report": tool_input["report"]})
        else:
            result = {"error": f"Unknown tool: {tool_name}"}

        return json.dumps(result)
    except ValueError as e:
        # Scope violation
        return json.dumps({"error": str(e), "blocked": True})
    except Exception as e:
        return json.dumps({"error": f"Tool execution failed: {str(e)}"})


class OSINTAgent:
    def __init__(self, scope: Scope, verbose: bool = True):
        self.scope = scope
        self.validator = ScopeValidator(scope)
        self.verbose = verbose
        self.messages = []
        self.final_report = None

    def log(self, msg: str):
        if self.verbose:
            print(f"[OSINT] {msg}")

    def run(self, target: str, objective: str = None) -> dict:
        """Run the OSINT agent against a target."""
        # Validate primary target
        valid, reason = self.validator.validate(target)
        if not valid:
            return {"error": reason}

        objective = objective or f"Perform comprehensive OSINT reconnaissance on {target}"

        self.log(f"Starting OSINT reconnaissance on {target}")
        self.messages = [{"role": "user", "content": f"{objective}\n\nPrimary target: {target}"}]

        max_iterations = 20
        iteration = 0

        while iteration < max_iterations:
            iteration += 1
            self.log(f"Agent thinking... (iteration {iteration})")

            response = client.messages.create(
                model=DEFAULT_MODEL,
                max_tokens=4096,
                system=OSINT_SYSTEM_PROMPT,
                tools=OSINT_TOOLS,
                messages=self.messages,
                timeout_s=OLLAMA_TIMEOUT_S,
                max_retries=OLLAMA_MAX_RETRIES,
            )

            # Add assistant response to history
            self.messages.append({"role": "assistant", "content": response.content})

            # Check stop condition
            if response.stop_reason == "end_turn":
                self.log("Agent completed reconnaissance")
                break

            # Process tool calls
            if response.stop_reason == "tool_use":
                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        self.log(f"Calling tool: {block.name}({json.dumps(block.input)[:100]}...)")
                        result = execute_tool(block.name, block.input, self.validator)

                        # Check if final report was compiled
                        parsed = json.loads(result)
                        if parsed.get("status") == "report_compiled":
                            report_obj = parsed.get("report") or {}
                            if isinstance(report_obj, dict):
                                self.final_report = report_obj
                            else:
                                self.final_report = {
                                    "status": "partial",
                                    "errors": ["invalid_report"],
                                    "summary": "OSINT report was not a JSON object.",
                                }

                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result
                        })

                self.messages.append({"role": "user", "content": tool_results})

        # Extract final report
        if not self.final_report:
            # Try to extract from last message
            for block in self.messages[-2]["content"] if len(self.messages) >= 2 else []:
                if hasattr(block, "text"):
                    try:
                        # Try to find JSON in the text
                        text = block.text
                        start = text.find("{")
                        end = text.rfind("}") + 1
                        if start != -1 and end > start:
                            self.final_report = json.loads(text[start:end])
                    except Exception:
                        self.final_report = {
                            "status": "partial",
                            "errors": ["no_final_report"],
                            "summary": str(text)[:500],
                        }

        return self.final_report or {
            "status": "partial",
            "errors": ["no_final_report"],
            "summary": "OSINT agent ended without a final report.",
        }
