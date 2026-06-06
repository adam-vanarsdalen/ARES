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
from utils.config import ENABLE_MANUAL_SECRET_VERIFY, OLLAMA_MAX_RETRIES, OLLAMA_TIMEOUT
from utils.scope_validator import ScopeValidator, Scope
from tools.secret_workbench import verify_operator_secret
from tools.redteam_verification import (
    discover_auth_panels,
    enumerate_api_endpoints,
    test_clickjacking,
    test_host_header_injection,
    test_http_methods,
    test_open_redirect,
)

client = Anthropic()
OLLAMA_TIMEOUT_S = OLLAMA_TIMEOUT
_RAW_SECRET_KEYS = {
    "access_token",
    "api_key",
    "key",
    "password",
    "raw",
    "raw_secret",
    "secret",
    "secret_access_key",
    "secret_value",
    "session_token",
    "token",
    "value",
}

REDTEAM_SYSTEM_PROMPT = """You are ARES-REDTEAM, a verification-only security assessment agent.

You receive vulnerability intelligence from previous reconnaissance phases and your job is to:
1. Perform NON-DESTRUCTIVE verification checks (metadata and indicators only)
2. Confirm only what you can support with evidence from tool results
3. Document everything for the final security report

YOU MUST:
- ONLY act against targets in defined scope
- Perform NON-DESTRUCTIVE testing only — do not delete, modify, or exfiltrate data
- In advanced/custom profile context, attempt at least one relevant non-destructive verification for each confirmed or evidence-backed recon finding
- Distinguish confirmed, strongly_indicated, not_reproduced, blocked_by_roe, and needs_manual_followup
- Prefer evidence-backed verification over speculation
- Treat redacted exposed keys, tokens, and secrets as high-priority manual verification candidates
- Mark discovered or redacted secret findings needs_manual_verification and recommend rotation
- Use verify_operator_secret only when an operator-supplied volatile secret is available in the workbench context
- Never reveal or persist a raw secret value
- Do NOT provide exploit payloads or step-by-step exploitation instructions
- Log every action taken for the report

YOU MUST NOT:
- Test any target not explicitly in scope
- Attempt credentials or use discovered credentials
- Submit forms
- Execute destructive payloads
- Perform destructive writes
- Exfiltrate real sensitive data
- Perform DoS attacks
- Attempt to verify a redacted or discovered secret value

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
        "name": "test_open_redirect",
        "description": "Verify candidate open redirects with a non-routable marker URL. Returns verification status, tested parameters, and the next manual test.",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "In-scope endpoint URL to verify"}},
            "required": ["url"]
        }
    },
    {
        "name": "test_http_methods",
        "description": "Perform non-destructive OPTIONS and TRACE method exposure checks. PUT/DELETE are not available through this agent tool.",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "In-scope URL to check"}},
            "required": ["url"]
        }
    },
    {
        "name": "test_clickjacking",
        "description": "Check X-Frame-Options and CSP frame-ancestors without submitting forms. Returns status and next manual framing test.",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "In-scope page URL"}},
            "required": ["url"]
        }
    },
    {
        "name": "test_host_header_injection",
        "description": "Check for reflection of a harmless invalid Host marker. Does not send credentials or modify server state.",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "In-scope endpoint URL"}},
            "required": ["url"]
        }
    },
    {
        "name": "enumerate_api_endpoints",
        "description": "Probe a capped built-in list of common API documentation and endpoint paths with GET. HTTP 401/403 confirms surface only.",
        "input_schema": {
            "type": "object",
            "properties": {"base_url": {"type": "string", "description": "In-scope base URL"}},
            "required": ["base_url"]
        }
    },
    {
        "name": "discover_auth_panels",
        "description": "Enumerate common admin/login panel paths without credential attempts. Returns reachable protected surface and manual guidance.",
        "input_schema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Base URL (include scheme) e.g. https://example.com"}
            },
            "required": ["base_url"]
        }
    },
    {
        "name": "discover_admin_panels",
        "description": "Compatibility alias for discover_auth_panels. No credential guessing or authentication attempts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "In-scope base URL"}
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
        "name": "verify_operator_secret",
        "description": "Verify metadata for an operator-supplied volatile secret already present in the manual workbench context. Never accepts or uses redacted/discovered stored values and never persists the secret.",
        "input_schema": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "description": "Provider for the operator-supplied workbench value",
                },
                "perform_metadata_check": {
                    "type": "boolean",
                    "description": "Whether to perform the provider's metadata-only verification",
                },
            },
            "required": ["provider"],
        },
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


def _sanitize_report_secrets(value):
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            normalized = str(key).lower()
            if normalized in _RAW_SECRET_KEYS or normalized.startswith("raw_"):
                continue
            sanitized[key] = _sanitize_report_secrets(item)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_report_secrets(item) for item in value]
    return value


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


def execute_tool(
    tool_name: str,
    tool_input: dict,
    scope: ScopeValidator,
    volatile_secret_context: dict | None = None,
) -> str:
    try:
        if tool_name in {"discover_admin_panels", "discover_auth_panels"}:
            result = discover_auth_panels(tool_input["base_url"], scope)
        elif tool_name == "test_open_redirect":
            result = test_open_redirect(tool_input["url"], scope)
        elif tool_name == "test_http_methods":
            result = test_http_methods(tool_input["url"], scope)
        elif tool_name == "test_clickjacking":
            result = test_clickjacking(tool_input["url"], scope)
        elif tool_name == "test_host_header_injection":
            result = test_host_header_injection(tool_input["url"], scope)
        elif tool_name == "enumerate_api_endpoints":
            result = enumerate_api_endpoints(tool_input["base_url"], scope)
        elif tool_name == "test_cors_misconfiguration":
            result = test_cors_misconfiguration(tool_input["url"], scope)
        elif tool_name == "verify_operator_secret":
            context = volatile_secret_context or {}
            if not ENABLE_MANUAL_SECRET_VERIFY or not context.get("secret_value"):
                result = {
                    "status": "needs_manual_verification",
                    "manual_verification_required": True,
                    "rotation_recommended": True,
                    "raw_secret_stored": False,
                    "reason": "No enabled operator-supplied volatile secret context is available.",
                }
            else:
                provider = str(tool_input.get("provider") or context.get("provider") or "generic")
                result = verify_operator_secret(
                    provider,
                    context["secret_value"],
                    perform_metadata_check=bool(tool_input.get("perform_metadata_check", False)),
                    secret_access_key=str(context.get("secret_access_key") or ""),
                    session_token=str(context.get("session_token") or ""),
                )
        elif tool_name == "compile_redteam_report":
            return json.dumps({"status": "report_compiled", "report": tool_input["report"]})
        else:
            result = {
                "status": "skipped",
                "error": f"Unknown tool: {tool_name}",
                "blocked": True,
            }
        return json.dumps(result)
    except ValueError as e:
        return json.dumps({"error": str(e), "blocked": True})
    except Exception as e:
        return json.dumps({"error": f"Tool execution failed: {str(e)}"})


class RedTeamAgent:
    def __init__(
        self,
        scope: Scope,
        verbose: bool = True,
        volatile_secret_context: dict | None = None,
    ):
        self.scope = scope
        self.validator = ScopeValidator(scope)
        self.verbose = verbose
        self.volatile_secret_context = volatile_secret_context or {}
        self.final_report = None

    def log(self, msg: str):
        if self.verbose:
            print(f"[REDTEAM] {msg}")

    def run(self, vuln_report: dict) -> dict:
        """Run red team testing based on vulnerability report."""
        self.log("Starting authorized red team testing")

        secret_context_status = (
            f"available for provider {self.volatile_secret_context.get('provider', 'generic')}"
            if self.volatile_secret_context.get("secret_value")
            else "not available"
        )
        safe_vuln_report = _sanitize_report_secrets(vuln_report)
        prompt = f"""Based on this vulnerability assessment, perform authorized red team verification.
Focus on evidence-backed findings and attempt to verify the reported condition without exploitation.

VULNERABILITY REPORT:
{json.dumps(safe_vuln_report, indent=2)}

OPERATOR-SUPPLIED VOLATILE SECRET CONTEXT: {secret_context_status}

Test each finding methodically. Document all attempts and results.
Redacted or discovered secrets require manual verification and rotation guidance. Only the
verify_operator_secret tool may use an available operator-supplied volatile workbench value.
Never attempt credentials, submit forms, test discovered secrets, reveal raw values, or perform writes.
Classify outcomes as confirmed, strongly_indicated, not_reproduced, blocked_by_roe,
or needs_manual_followup. Confirm evidence, not exploitability."""

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
                        result = execute_tool(
                            block.name,
                            block.input,
                            self.validator,
                            self.volatile_secret_context,
                        )
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
