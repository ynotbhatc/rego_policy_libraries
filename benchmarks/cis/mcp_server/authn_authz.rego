package cis_mcp_server.authn_authz

import rego.v1

# CIS MCP Server Benchmark v1.0.0 — Section 3: Authentication and Authorization.
# Coverage note: implemented from the recommendation set verifiable in public
# sources (the Astrix CIS-MCP-Benchmark-Prober project's published check
# documentation, 2026-09) — 46 of the benchmark's 55 recommendations across 7
# of its 10 sections. Sections 6 (Data Protection and Privacy), 8 (Supply
# Chain Security), and 9 (Isolation and Execution Safety) await the benchmark
# PDF and are NOT implemented; the orchestrator states this coverage
# explicitly. Do not present this module set as full-benchmark coverage.
requirements := {
	"3.1.1": {"section": 3, "level": "L1", "title": "stdio server credentials are sourced from the environment or OS credential store"},
	"3.1.2": {"section": 3, "level": "L1", "title": "OIDC/OAuth 2.1 or short-lived API tokens are used for remote servers"},
	"3.2.1": {"section": 3, "level": "L2", "title": "Per-tool authorization policies are enforced"},
	"3.2.2": {"section": 3, "level": "L1", "title": "Token passthrough to downstream APIs is forbidden"},
	"3.2.3": {"section": 3, "level": "L1", "title": "Server-provided tool annotations are not relied upon for authorization or human-in-the-loop gating"},
	"3.3.1": {"section": 3, "level": "L1", "title": "OAuth tokens are audience-bound to the MCP server using Resource Indicators"},
	"3.3.2": {"section": 3, "level": "L2", "title": "OAuth discovery metadata is served over TLS and validated against the approved list"},
	"3.3.3": {"section": 3, "level": "L2", "title": "Shared downstream service account identities are prohibited across tools and servers"},
	"3.3.4": {"section": 3, "level": "L2", "title": "OAuth scopes are minimized and elevated progressively"},
	"3.3.5": {"section": 3, "level": "L2", "title": "Confused-deputy safeguards are applied for static OAuth client IDs"},
}

attested(id) if input.cis_mcp_server.authn_authz.requirements[id] == true

# Fail closed: an unattested recommendation is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CIS MCP %s: %s — not met", [id, m.title])
}

default section_compliant := false

section_compliant if count(violation) == 0

compliance_report := {
	"section": 3,
	"area_name": "Authentication and Authorization",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": section_compliant,
}
