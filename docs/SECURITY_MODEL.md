# ARES Security Model

## Enforcement Order

ARES evaluates target scope, profile, feature flags, RoE profile permission,
forbidden domains/paths, method allowlists, risky-path allowlists, and lab target
classification before a governed action runs.

Target URLs and every redirect destination are normalized and DNS-resolved.
Private, loopback, link-local, multicast, reserved, and unspecified addresses
are denied by default. Redirect bodies are not fetched when the next hop fails
scope or network policy validation.

## Rules of Engagement

RoE YAML can declare domains, IPs, CIDRs, forbidden paths, allowed methods,
risky methods, exact risky paths, profiles, lab targets, request limits, and
custom capabilities. Advanced operation requires RoE by default.

API clients select a policy ID, never a filesystem path. IDs resolve only
inside `ARES_ROE_POLICY_DIR`; absolute paths, traversal, unknown IDs, and
symlinks escaping the approved directory are rejected. Without a policy, ARES
uses an exact-host public scope and does not authorize subdomains automatically.

## Evidence and Audit

Evidence records contain redacted request/response metadata, body hashes,
reproduction hints, scope/RoE/capability decisions, and
`raw_secret_stored=false`. Audit events form a SHA-256 chain; replay JSON combines
the audit timeline, evidence, and redacted LLM metadata.

## Secret Handling

Discovered values are never automatically tested. The optional workbench accepts
operator-supplied values in volatile secret types and returns only format,
metadata, redacted identity, scope, and rotation guidance. Raw values are not
logged, persisted, reported, streamed, or traced.

The workbench additionally requires the server's effective profile to be
advanced/custom, the advanced feature flag, an RoE authorization decision, and
explicit operator confirmation. A client-supplied profile cannot grant access.

## Lab Simulation

Exploit-chain simulation is limited to localhost or manifest-declared demo
assets. Output always sets `lab_only=true` and
`real_target_execution_allowed=false`.

## Nuclei

`safe` uses non-destructive exposure/misconfiguration tags. `moderate` requires
advanced/custom plus RoE. `custom` requires explicit template IDs. Destructive,
RCE, DoS, credential, file-write, brute-force, intrusive, and fuzz tags are
blocked for real targets. Custom template IDs must be allowlisted by RoE and
must have inspected metadata unless the custom RoE explicitly records an
uninspected-template exception. Interactsh is disabled.

## Plugins

Active network plugins must declare scope requirements. Advanced/lab plugins
must declare RoE requirements. External plugins are disabled by default, and
registry execution normalizes output and evidence.

ARES does not implement credential stuffing, default credential attempts,
destructive real-target writes, automatic discovered-credential use,
real-target exploit payload automation, malware, persistence, evasion, or
post-exploitation.
