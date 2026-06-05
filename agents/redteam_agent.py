"""
ARES — Red Team Agent
Verification-only assessment agent.
ONLY operates against explicitly authorized targets.
Designed for: CTF environments, authorized bug bounty targets, your own infrastructure.
"""

import json
import subprocess
import urllib.request
import urllib.parse
import ssl
from ollama_compat import OllamaClient as Anthropic, DEFAULT_MODEL, ollama_chat
from utils.config import OLLAMA_MAX_RETRIES, OLLAMA_TIMEOUT
from utils.scope_validator import ScopeValidator, Scope

client = Anthropic()
OLLAMA_TIMEOUT_S = OLLAMA_TIMEOUT

REDTEAM_SYSTEM_PROMPT = """You are ARES-REDTEAM, a verification-only security assessment agent.

You receive vulnerability intelligence from previous reconnaissance phases and your job is to:
1. Perform NON-DESTRUCTIVE verification checks (metadata and indicators only)
2. Confirm only what you can support with evidence from tool results
3. Document everything for the final security report

YOU MUST:
- ONLY act against targets in defined scope
- Perform NON-DESTRUCTIVE testing only — do not delete, modify, or exfiltrate data
- Do NOT provide exploit payloads or step-by-step exploitation instructions
- Log every action taken for the report

YOU MUST NOT:
- Test any target not explicitly in scope
- Execute destructive payloads
- Exfiltrate real sensitive data
- Perform DoS attacks

Think like a professional penetration tester bound by rules of engagement.

Output the FINAL report ONLY via the compile_redteam_report tool.
The report must be valid JSON matching this shape (no extra keys):
{
  "status": "ok|partial|error",
  "errors": ["..."],
  "confirmed_vulnerabilities": [{"name":"...","severity":"HIGH","evidence":"...","exploitable":false,"evidence_ids":["..."],"hypothesis":false}],
  "proof_of_concepts": [{"name":"...","result":"...","evidence_ids":["..."]}],
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "engagement_summary": "...",
  "recommendations": [{"priority":"HIGH","recommendation":"defensive hardening step"}],
  "evidence": [{"evidence_id":"...","source":"other","summary":"..."}]
}"""

REDTEAM_TOOLS = [
    {
        "name": "discover_admin_panels",
        "description": "Enumerate common admin/login panel paths (NO credential guessing; metadata only).",
        "input_schema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Base URL (include scheme) e.g. https://example.com"}
            },
            "required": ["base_url"]
        }
    },
    {
        "name": "test_cors_misconfiguration",
        "description": "Check if CORS headers reflect an arbitrary Origin (metadata only).",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Endpoint URL to check"}
            },
            "required": ["url"]
        }
    },
    {
        "name": "compile_redteam_report",
        "description": "Compile final red team assessment report. Call when testing is complete.",
        "input_schema": {
            "type": "object",
            "properties": {
                "report": {"type": "object", "description": "Complete red team report"}
            },
            "required": ["report"]
        }
    }
]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _urlopen_no_redirect(req: urllib.request.Request, timeout: int, ctx: ssl.SSLContext):
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    return opener.open(req, timeout=timeout)


def discover_admin_panels(base_url: str, scope: ScopeValidator) -> dict:
    """
    Non-destructive metadata check: probes common admin/login paths and reports which are reachable.
    Does NOT attempt authentication or brute-force credentials.
    """
    scope.assert_in_scope(base_url)
    base = base_url.rstrip("/")
    common_paths = ["/admin", "/admin/login", "/login", "/wp-admin", "/user/login"]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    reachable = []
    for path in common_paths:
        url = base + path
        try:
            scope.assert_in_scope(url)
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with _urlopen_no_redirect(req, timeout=6, ctx=ctx) as resp:
                status = int(getattr(resp, "status", 0) or 0)
                if status in {200, 401, 403}:
                    reachable.append({"path": path, "status": status})
        except urllib.error.HTTPError as e:
            if int(getattr(e, "code", 0) or 0) in {401, 403}:
                reachable.append({"path": path, "status": int(e.code)})
        except Exception:
            pass

    return {"base_url": base_url, "reachable": reachable, "tested": len(common_paths)}


def test_cors_misconfiguration(url: str, scope: ScopeValidator) -> dict:
    """Test CORS policy."""
    scope.assert_in_scope(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={
            "Origin": "https://evil.com",
            "User-Agent": "Mozilla/5.0"
        })
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            vulnerable = acao in ["*", "https://evil.com"] or "evil.com" in acao
            return {
                "url": url,
                "Access-Control-Allow-Origin": acao,
                "Access-Control-Allow-Credentials": acac,
                "cors_misconfigured": vulnerable,
                "severity": "HIGH" if (vulnerable and acac == "true") else "MEDIUM" if vulnerable else "OK"
            }
    except Exception as e:
        return {"url": url, "error": str(e)}


def execute_tool(tool_name: str, tool_input: dict, scope: ScopeValidator) -> str:
    try:
        if tool_name == "discover_admin_panels":
            result = discover_admin_panels(tool_input["base_url"], scope)
        elif tool_name == "test_cors_misconfiguration":
            result = test_cors_misconfiguration(tool_input["url"], scope)
        elif tool_name == "compile_redteam_report":
            return json.dumps({"status": "report_compiled", "report": tool_input["report"]})
        else:
            result = {"error": f"Unknown tool: {tool_name}"}
        return json.dumps(result)
    except ValueError as e:
        return json.dumps({"error": str(e), "blocked": True})
    except Exception as e:
        return json.dumps({"error": f"Tool execution failed: {str(e)}"})


class RedTeamAgent:
    def __init__(self, scope: Scope, verbose: bool = True):
        self.scope = scope
        self.validator = ScopeValidator(scope)
        self.verbose = verbose
        self.final_report = None

    def log(self, msg: str):
        if self.verbose:
            print(f"[REDTEAM] {msg}")

    def run(self, vuln_report: dict) -> dict:
        """Run red team testing based on vulnerability report."""
        self.log("Starting authorized red team testing")

        prompt = f"""Based on this vulnerability assessment, perform authorized red team testing.
Focus on the highest-severity findings and attempt to confirm their exploitability.

VULNERABILITY REPORT:
{json.dumps(vuln_report, indent=2)}

Test each finding methodically. Document all attempts and results.
Remember: NON-DESTRUCTIVE testing only. Confirm access, don't abuse it."""

        messages = [{"role": "user", "content": prompt}]
        max_iterations = 20
        iteration = 0

        while iteration < max_iterations:
            iteration += 1
            self.log(f"Testing... (iteration {iteration})")

            response = client.messages.create(
                model=DEFAULT_MODEL,
                max_tokens=4096,
                system=REDTEAM_SYSTEM_PROMPT,
                tools=REDTEAM_TOOLS,
                messages=messages,
                timeout_s=OLLAMA_TIMEOUT_S,
                max_retries=OLLAMA_MAX_RETRIES,
            )

            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                break

            if response.stop_reason == "tool_use":
                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        self.log(f"Testing: {block.name}")
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
                                    "engagement_summary": "Redteam report was not a JSON object.",
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
            "engagement_summary": "Redteam agent ended without a final report.",
        }
