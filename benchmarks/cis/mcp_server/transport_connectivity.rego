package cis_mcp_server.transport_connectivity

import rego.v1

# CIS MCP Server Benchmark v1.0.0 — Section 2: Transport and Connectivity.
# Coverage note: implemented from the recommendation set verifiable in public
# sources (the Astrix CIS-MCP-Benchmark-Prober project's published check
# documentation, 2026-09) — 46 of the benchmark's 55 recommendations across 7
# of its 10 sections. Sections 6 (Data Protection and Privacy), 8 (Supply
# Chain Security), and 9 (Isolation and Execution Safety) await the benchmark
# PDF and are NOT implemented; the orchestrator states this coverage
# explicitly. Do not present this module set as full-benchmark coverage.
requirements := {
	"2.1": {"section": 2, "level": "L1", "title": "stdio transport is preferred for local, single-user servers over network transports"},
	"2.2": {"section": 2, "level": "L1", "title": "TLS is required: plaintext refused, obsolete TLS versions refused, certificate valid"},
	"2.3": {"section": 2, "level": "L2", "title": "Authentication is enforced before a streamed (SSE) response is established, including through proxies"},
	"2.4": {"section": 2, "level": "L1", "title": "Required request metadata headers are present and consistent with the body"},
	"2.5": {"section": 2, "level": "L1", "title": "The Origin header is validated on all requests; hostile origins are refused"},
}

attested(id) if input.cis_mcp_server.transport_connectivity.requirements[id] == true

# Fail closed: an unattested recommendation is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CIS MCP %s: %s — not met", [id, m.title])
}

default section_compliant := false

section_compliant if count(violation) == 0

compliance_report := {
	"section": 2,
	"area_name": "Transport and Connectivity",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": section_compliant,
}
