"""
ARES — Attack Graph & Kill Chain Engine
Builds a graph of discovered assets and findings, then reasons about
exploitation chains — how an attacker could pivot from one finding to
achieve progressively deeper access.

This is what separates a CVE list from an actual penetration test.
Example chain:
  nginx 1.19.0 CVE → directory traversal → reads .env file →
  contains DB credentials → DB is exposed on port 3306 →
  full database dump → contains admin password hash →
  hash cracked → admin panel login → RCE via file upload

Uses the AI model to reason about chains given the discovered asset graph.
"""

import json
import hashlib
import logging
import re


logger = logging.getLogger(__name__)


# ── MITRE ATT&CK Technique Mappings ──────────────────────────────────────────
# Maps finding types to ATT&CK techniques for blue team correlation
ATTACK_TECHNIQUE_MAP = {
    "subdomain": ("T1590.001", "Active Scanning: Scanning IP Blocks"),
    "cert_transparency": ("T1596.003", "Search Open Technical Databases: Digital Certificates"),
    "js_endpoint": ("T1083", "File and Directory Discovery"),
    "js_secret": ("T1552.001", "Unsecured Credentials: Credentials In Files"),
    "sql_injection": ("T1190", "Exploit Public-Facing Application"),
    "xss": ("T1059.007", "Command and Scripting Interpreter: JavaScript"),
    "ssrf": ("T1090.002", "Proxy: External Proxy"),
    "lfi": ("T1083", "File and Directory Discovery"),
    "default_creds": ("T1078.001", "Valid Accounts: Default Accounts"),
    "exposed_admin": ("T1133", "External Remote Services"),
    "exposed_git": ("T1552.001", "Unsecured Credentials: Credentials In Files"),
    "exposed_env": ("T1552.001", "Unsecured Credentials: Credentials In Files"),
    "cors": ("T1557", "Adversary-in-the-Middle"),
    "cve_rce": ("T1190", "Exploit Public-Facing Application"),
    "cve_sqli": ("T1190", "Exploit Public-Facing Application"),
    "cve_auth_bypass": ("T1190", "Exploit Public-Facing Application"),
    "outdated_software": ("T1190", "Exploit Public-Facing Application"),
    "open_port_db": ("T1433", "Access Contact List"),
    "cloud_storage": ("T1530", "Data from Cloud Storage"),
    "internal_host": ("T1018", "Remote System Discovery"),
}

# Finding severity weights for graph scoring
SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}

_ID_HASH_LEN = 12


def _stable_id(kind: str, *parts: object) -> str:
    """Stable, deterministic ID builder to avoid collisions across node kinds."""
    material = "\x1f".join([kind, *[str(p) for p in parts]])
    digest = hashlib.sha1(material.encode("utf-8", errors="ignore")).hexdigest()[:_ID_HASH_LEN]
    return f"{kind}:{digest}"


def _normalize_technology_stack(value: object) -> list[str]:
    """
    Accept None, str, list[str], dict, list[dict] without throwing.
    Normalizes to list[str] suitable for graph asset nodes.
    """
    if not value:
        return []

    def coerce_one(item: object) -> str | None:
        if item is None:
            return None
        if isinstance(item, str):
            s = item.strip()
            return s or None
        if isinstance(item, dict):
            name = str(item.get("name") or item.get("technology") or "").strip()
            version = str(item.get("version") or "").strip()
            if name and version:
                return f"{name} {version}".strip()
            if name:
                return name
            if len(item) == 1:
                k, v = next(iter(item.items()))
                s = f"{k} {v}".strip()
                return s or None
            return None
        return None

    if isinstance(value, list):
        out: list[str] = []
        unknown = 0
        for item in value:
            s = coerce_one(item)
            if s:
                out.append(s)
            else:
                unknown += 1
        if unknown:
            logger.warning("attack_graph: dropped %d unrecognized technology_stack entries", unknown)
        return out

    s = coerce_one(value)
    if s:
        return [s]
    logger.warning("attack_graph: unrecognized technology_stack type=%s", type(value).__name__)
    return []


def _technique_for_node_id(node_id: str) -> tuple[str, str]:
    """Map internal node IDs (kind-prefixed) to ATT&CK technique ID/name."""
    kind = (node_id.split(":", 1)[0] if node_id else "").lower()
    alias = {
        "ct_sub": "cert_transparency",
        "js_secret": "js_secret",
        "internal_host": "internal_host",
        "cloud": "cloud_storage",
        "misconfig": "outdated_software",
        "credential_exposure": "exposed_env",
        "cve": "outdated_software",
        "active_exploit": "cve_rce",
        "js_endpoints": "js_endpoint",
        "subdomain": "subdomain",
    }.get(kind)
    if alias and alias in ATTACK_TECHNIQUE_MAP:
        return ATTACK_TECHNIQUE_MAP[alias]
    return ("T1190", "Exploit Public-Facing Application")


def _parent_for_affected(affected: str, tech_stack: list[str], tech_id_by_index: list[str], default_parent: str) -> str:
    affected_l = (affected or "").lower()
    if not affected_l:
        return default_parent
    for idx, tech in enumerate(tech_stack):
        tech_l = tech.lower()
        tech_name = tech_l.split(" ")[0]
        if tech_l in affected_l or affected_l in tech_l or tech_name in affected_l:
            if idx < len(tech_id_by_index):
                return tech_id_by_index[idx]
    return default_parent


class AttackNode:
    """Represents a discovered asset or finding in the attack graph."""
    def __init__(self, node_id: str, node_type: str, label: str,
                 severity: str = "INFO", data: dict = None):
        self.id = node_id
        self.type = node_type        # asset | finding | credential | service
        self.label = label
        self.severity = severity
        self.data = data or {}
        self.edges = []              # list of (target_node_id, relationship_label)

    def connect(self, target_id: str, relationship: str):
        self.edges.append((target_id, relationship))

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "severity": self.severity,
            "data": self.data,
            "edges": self.edges
        }


class AttackGraph:
    """Directed graph of assets and attack paths."""
    def __init__(self, target: str):
        self.target = target
        self.nodes: dict[str, AttackNode] = {}
        self.root_id = f"target:{target}"
        self._add_node(self.root_id, "asset", f"Target: {target}", "INFO")

    def _add_node(self, node_id: str, node_type: str, label: str,
                  severity: str = "INFO", data: dict = None) -> AttackNode:
        if node_id not in self.nodes:
            self.nodes[node_id] = AttackNode(node_id, node_type, label, severity, data)
        return self.nodes[node_id]

    def add_finding(self, finding_id: str, label: str, severity: str,
                    parent_id: str = None, data: dict = None, relationship: str = "exposes"):
        node = self._add_node(finding_id, "finding", label, severity, data)
        parent = parent_id or self.root_id
        if parent in self.nodes:
            self.nodes[parent].connect(finding_id, relationship)
        return node

    def add_asset(self, asset_id: str, label: str, parent_id: str = None,
                  data: dict = None, relationship: str = "has"):
        node = self._add_node(asset_id, "asset", label, "INFO", data)
        parent = parent_id or self.root_id
        if parent in self.nodes:
            self.nodes[parent].connect(asset_id, relationship)
        return node

    def get_critical_paths(self) -> list[list[str]]:
        """Find all paths from root to CRITICAL/HIGH severity nodes."""
        paths = []
        def dfs(node_id, current_path, visited):
            if node_id in visited:
                return
            visited = visited | {node_id}
            current_path = current_path + [node_id]
            node = self.nodes.get(node_id)
            if not node:
                return
            if node.severity in ("CRITICAL", "HIGH") and len(current_path) > 1:
                paths.append(current_path[:])
            for target_id, _ in node.edges:
                dfs(target_id, current_path, visited)
        dfs(self.root_id, [], set())
        return paths

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "node_count": len(self.nodes),
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
            "critical_paths": self.get_critical_paths()
        }


def build_attack_graph(
    target: str,
    osint_data: dict,
    recon_data: dict,
    ct_data: dict = None,
    js_data: dict = None,
) -> AttackGraph:
    """
    Build the attack graph from all collected intelligence.
    Connects assets → findings → potential pivots.
    """
    graph = AttackGraph(target)

    # ── OSINT nodes ───────────────────────────────────────────────────────────
    tech_stack = _normalize_technology_stack(osint_data.get("technology_stack"))
    tech_id_by_index: list[str] = []
    for idx, tech in enumerate(tech_stack):
        tid = _stable_id("tech", tech, idx)
        tech_id_by_index.append(tid)
        graph.add_asset(tid, f"Software: {tech}", relationship="runs")

    # Subdomains
    for sub in osint_data.get("subdomains", []):
        subdomain = sub.get("subdomain", sub) if isinstance(sub, dict) else sub
        ip = sub.get("ip", "") if isinstance(sub, dict) else ""
        sid = _stable_id("subdomain", subdomain)
        graph.add_asset(sid, f"Subdomain: {subdomain}" + (f" ({ip})" if ip else ""),
                        relationship="has_subdomain")

    # ── CT subdomains ─────────────────────────────────────────────────────────
    if ct_data:
        for idx, sub in enumerate(ct_data.get("interesting_subdomains", [])):
            cid = _stable_id("ct_sub", sub.get("subdomain", ""), idx)
            graph.add_finding(
                cid, f"CT Subdomain (interesting): {sub['subdomain']}",
                severity="MEDIUM",
                data={"ip": sub.get("ip"), "source": "certificate_transparency"},
                relationship="ct_discovered"
            )

    # ── Misconfigs ────────────────────────────────────────────────────────────
    misconfig_parent = f"target:{target}"
    for finding in osint_data.get("_misconfigs", []):
        path = finding.get("path", "")
        severity = finding.get("severity", "INFO")
        fid = _stable_id("misconfig", path)
        graph.add_finding(
            fid, f"Exposed path: {path}",
            severity=severity,
            parent_id=misconfig_parent,
            data=finding,
            relationship="exposes"
        )
        # Connect env/git files to credential theft chain
        if path in ("/.env", "/.git/config", "/wp-config.php", "/database.yml"):
            cred_id = _stable_id("credential_exposure", path)
            graph.add_finding(
                cred_id, f"Potential credential exposure via {path}",
                severity="CRITICAL",
                parent_id=fid,
                data={"chain_step": "credential_theft"},
                relationship="enables"
            )

    # ── CVE findings ──────────────────────────────────────────────────────────
    for idx, cve in enumerate(recon_data.get("cve_matches", [])):
        cve_id = cve.get("id", "")
        cvss = cve.get("cvss_score") or 0
        epss = cve.get("epss", 0)
        severity = "CRITICAL" if cvss >= 9.0 else "HIGH" if cvss >= 7.0 else "MEDIUM"

        # Find which tech this CVE affects
        description = cve.get("description", "").lower()
        parent_id = misconfig_parent
        for t_idx, tech in enumerate(tech_stack):
            tech_name = tech.split(" ")[0].lower()
            if tech_name in description or tech_name in cve_id.lower():
                if t_idx < len(tech_id_by_index):
                    parent_id = tech_id_by_index[t_idx]
                break

        fid = _stable_id("cve", cve_id or "", cve.get("published", ""), cve.get("description", "")[:80], idx)
        graph.add_finding(
            fid,
            f"{cve_id} (CVSS {cvss}" + (f", EPSS {epss*100:.1f}%" if epss else "") + ")",
            severity=severity,
            parent_id=parent_id,
            data=cve,
            relationship="vulnerable_to"
        )

        # Connect high-epss CVEs to active exploitation node
        if epss >= 0.1:
            graph.add_finding(
                _stable_id("active_exploit", cve_id or "", epss, idx),
                f"Active exploitation in wild ({epss*100:.1f}% probability)",
                severity="CRITICAL",
                parent_id=fid,
                data={"epss": epss, "cve": cve_id},
                relationship="actively_exploited_via"
            )

    # ── Recon findings ────────────────────────────────────────────────────────
    for idx, port_line in enumerate(recon_data.get("_open_ports", [])):
        service_id = _stable_id("service", port_line, idx)
        graph.add_asset(
            service_id,
            f"Service: {port_line}",
            parent_id=graph.root_id,
            data={"source": "port_scan"},
            relationship="exposes_service",
        )

    for severity_key, severity in (
        ("critical_findings", "CRITICAL"),
        ("high_findings", "HIGH"),
        ("medium_findings", "MEDIUM"),
    ):
        for idx, finding in enumerate(recon_data.get(severity_key, [])):
            title = finding.get("title") or finding.get("id") or f"{severity.title()} finding"
            description = finding.get("description", "")
            affected = finding.get("affected", "")
            parent_id = _parent_for_affected(affected, tech_stack, tech_id_by_index, misconfig_parent)
            fid = _stable_id("recon_finding", severity_key, title, affected, idx)
            graph.add_finding(
                fid,
                title,
                severity=severity,
                parent_id=parent_id,
                data=finding,
                relationship="identified"
            )

    # ── JS intelligence ───────────────────────────────────────────────────────
    if js_data:
        if js_data.get("secrets"):
            for idx, secret in enumerate(js_data["secrets"]):
                sid = _stable_id(
                    "js_secret",
                    secret.get("type", ""),
                    secret.get("value_preview", ""),
                    secret.get("full_length", ""),
                    idx,
                )
                graph.add_finding(
                    sid,
                    f"Hardcoded {secret['type']} in JavaScript ({secret['value_preview']})",
                    severity=secret.get("severity", "HIGH"),
                    data=secret,
                    relationship="leaks"
                )

        if js_data.get("internal_hosts"):
            for idx, host in enumerate(js_data["internal_hosts"]):
                graph.add_finding(
                    _stable_id("internal_host", host, idx),
                    f"Internal host reference: {host}",
                    severity="HIGH",
                    data={"host": host, "source": "js_analysis"},
                    relationship="reveals_internal"
                )

        if js_data.get("cloud_resources"):
            for idx, resource in enumerate(js_data["cloud_resources"][:5]):
                graph.add_finding(
                    _stable_id("cloud", resource.get("type", ""), resource.get("value", ""), idx),
                    f"{resource['type']}: {resource['value']}",
                    severity="MEDIUM",
                    data=resource,
                    relationship="exposes_cloud_resource"
                )

        if js_data.get("endpoints"):
            # Add a summary node for discovered API endpoints
            graph.add_finding(
                _stable_id("js_endpoints", "summary"),
                f"{len(js_data['endpoints'])} API endpoints discovered in JS",
                severity="MEDIUM",
                data={"endpoints": js_data["endpoints"][:20]},
                relationship="exposes_api"
            )

    return graph


def generate_kill_chains(graph: AttackGraph, ai_client, model: str) -> dict:
    """
    Use the AI model to reason about kill chains given the attack graph.
    Returns structured kill chain analysis.
    """
    # Build a condensed graph summary for the AI
    critical_nodes = [
        n for n in graph.nodes.values()
        if n.severity in ("CRITICAL", "HIGH")
    ]
    finding_nodes = [n for n in critical_nodes if n.type == "finding"]

    graph_summary = {
        "target": graph.target,
        "total_nodes": len(graph.nodes),
        "critical_findings": [
            {"id": n.id, "label": n.label, "severity": n.severity,
             "connects_to": [e[0] for e in n.edges]}
            for n in finding_nodes[:15]
        ],
        "critical_paths": graph.get_critical_paths()[:5]
    }

    prompt = f"""You are an expert red team analyst. Given this attack graph of discovered vulnerabilities and assets, 
identify the most dangerous exploitation chains an attacker could execute.

ATTACK GRAPH:
{json.dumps(graph_summary, indent=2)}

Reason through: which findings chain together? What's the worst-case scenario? 
What's the most realistic path to full compromise?

Return ONLY valid JSON:
{{
  "kill_chains": [
    {{
      "name": "Chain name e.g. 'PHP RCE to Database Exfiltration'",
      "likelihood": "HIGH",
      "steps": [
        {{"step": 1, "action": "...", "technique": "T1190", "finding": "finding_id"}},
        {{"step": 2, "action": "...", "technique": "T1552", "finding": "finding_id"}}
      ],
      "impact": "What the attacker achieves at end of chain",
      "mitre_tactics": ["Initial Access", "Credential Access"]
    }}
  ],
  "worst_case_scenario": "One paragraph describing full compromise path",
  "most_likely_attack": "The chain most likely to be attempted first",
  "overall_chain_risk": "CRITICAL"
}}

Generate 2-4 realistic kill chains based on the actual findings."""

    try:
        response = ai_client.messages.create(
            model=model,
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )
        text = response.content[0].text
        # Strip think tags
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
        text = re.sub(r"```(?:json)?\n?", "", text)
        text = re.sub(r"```", "", text)
        s, e = text.find("{"), text.rfind("}") + 1
        if s != -1 and e > s:
            return json.loads(text[s:e])
    except Exception:
        pass

    # Fallback: generate kill chains from graph structure directly
    chains = []
    critical_paths = graph.get_critical_paths()

    for i, path in enumerate(critical_paths[:3]):
        path_nodes = [graph.nodes[nid] for nid in path if nid in graph.nodes]
        steps = [
            {"step": j+1, "action": node.label,
             "technique": _technique_for_node_id(node.id)[0],
             "finding": node.id}
            for j, node in enumerate(path_nodes)
        ]
        severities = [n.severity for n in path_nodes]
        chain_risk = "CRITICAL" if "CRITICAL" in severities else "HIGH" if "HIGH" in severities else "MEDIUM"
        chains.append({
            "name": f"Attack Chain {i+1}",
            "likelihood": chain_risk,
            "steps": steps,
            "impact": f"Exploitation of {path_nodes[-1].label if path_nodes else 'target'}",
            "mitre_tactics": ["Initial Access", "Execution"]
        })

    return {
        "kill_chains": chains,
        "worst_case_scenario": (
            f"Target {graph.target} runs end-of-life software with known exploitable CVEs. "
            f"Discovered {len(critical_nodes)} high/critical findings across {len(graph.nodes)} assets. "
            f"Full compromise achievable via chained exploitation."
        ),
        "most_likely_attack": chains[0]["name"] if chains else "Direct CVE exploitation",
        "overall_chain_risk": "CRITICAL" if any(c["likelihood"] == "CRITICAL" for c in chains) else "HIGH"
    }


def map_to_mitre(findings: list[dict]) -> list[dict]:
    """Tag each finding with its MITRE ATT&CK technique."""
    tagged = []
    for finding in findings:
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        combined = title + " " + description

        technique_id, technique_name = "T1190", "Exploit Public-Facing Application"
        for keyword, (tid, tname) in ATTACK_TECHNIQUE_MAP.items():
            if keyword.replace("_", " ") in combined or keyword in combined:
                technique_id = tid
                technique_name = tname
                break

        tagged_finding = dict(finding)
        tagged_finding["mitre_technique"] = technique_id
        tagged_finding["mitre_technique_name"] = technique_name
        tagged_finding["mitre_url"] = f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"
        tagged.append(tagged_finding)

    return tagged
