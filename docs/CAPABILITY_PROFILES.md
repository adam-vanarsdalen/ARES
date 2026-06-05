# Capability Profiles

ARES separates operating intent from legacy pipeline mode.

## Passive

Permits DNS, WHOIS, certificate transparency, InternetDB, reverse-IP suggestions,
asset inventory, and reporting. Active HTTP behavior is disabled unless the
passive HTTP exception is explicitly enabled.

## Recon

Adds scoped HTTP probing, passive URL and JavaScript discovery, subdomain
enumeration, service scanning, TLS/version checks, CVE/EPSS enrichment, safe
Nuclei, and attack graph construction. It does not permit advanced verification.

## Advanced

Requires `ARES_ENABLE_ADVANCED_VERIFICATION=true` and a loaded RoE. It adds
non-destructive redirect, CORS, clickjacking, host-header, method, API, and
protected-path verification. Moderate Nuclei is allowed when separately enabled.
Zero-body PUT/DELETE checks require exact RoE method and path allowlists and
reject filename-like paths.

## Lab

Requires `ARES_ENABLE_LAB_EXPLOIT_SIMULATION=true`. It is restricted to
localhost, `.local`, Docker services, or CIDRs declared in the lab manifest.
Simulations never permit real-target execution.

## Custom

Requires an RoE `allowed_capabilities` list. Only named capabilities are
available. Custom Nuclei requires explicit template IDs and still blocks
destructive tags.

Profiles do not expand scope. Every network action remains subject to scope and
RoE decisions, and denied actions are retained as governance evidence.
