package cis_mcp_server.observability_audit

import rego.v1

# CIS MCP Server Benchmark v1.0.0 — Section 7: Observability and Audit.
# Coverage note: implemented from the recommendation set verifiable in public
# sources (the Astrix CIS-MCP-Benchmark-Prober project's published check
# documentation, 2026-09) — 46 of the benchmark's 55 recommendations across 7
# of its 10 sections. Sections 6 (Data Protection and Privacy), 8 (Supply
# Chain Security), and 9 (Isolation and Execution Safety) await the benchmark
# PDF and are NOT implemented; the orchestrator states this coverage
# explicitly. Do not present this module set as full-benchmark coverage.
requirements := {
	"7.1.1": {"section": 7, "level": "L1", "title": "Lifecycle and invocation metadata is recorded to a central audit log"},
	"7.1.2": {"section": 7, "level": "L1", "title": "Non-null JSON-RPC request IDs are enforced and included in audit logs"},
	"7.1.3": {"section": 7, "level": "unspecified", "title": "Audit records carry accurate, monotonic timestamps"},
	"7.2.1": {"section": 7, "level": "L1", "title": "Alerts are generated on audience and issuer validation failures"},
	"7.2.2": {"section": 7, "level": "L2", "title": "Cancellation and progress notifications are monitored for behavioral anomalies"},
}

attested(id) if input.cis_mcp_server.observability_audit.requirements[id] == true

# Fail closed: an unattested recommendation is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CIS MCP %s: %s — not met", [id, m.title])
}

default section_compliant := false

section_compliant if count(violation) == 0

compliance_report := {
	"section": 7,
	"area_name": "Observability and Audit",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": section_compliant,
}
