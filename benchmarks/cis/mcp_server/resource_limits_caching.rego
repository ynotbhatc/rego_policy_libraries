package cis_mcp_server.resource_limits_caching

import rego.v1

# CIS MCP Server Benchmark v1.0.0 — Section 10: Resource Limits and Caching.
# Coverage note: implemented from the recommendation set verifiable in public
# sources (the Astrix CIS-MCP-Benchmark-Prober project's published check
# documentation, 2026-09) — 46 of the benchmark's 55 recommendations across 7
# of its 10 sections. Sections 6 (Data Protection and Privacy), 8 (Supply
# Chain Security), and 9 (Isolation and Execution Safety) await the benchmark
# PDF and are NOT implemented; the orchestrator states this coverage
# explicitly. Do not present this module set as full-benchmark coverage.
requirements := {
	"10.1": {"section": 10, "level": "unspecified", "title": "Static resources are cached with freshness limits; per-user data is never shared-cached"},
	"10.2": {"section": 10, "level": "unspecified", "title": "Request/response body size limits, token budgets, and per-principal quotas are enforced"},
}

attested(id) if input.cis_mcp_server.resource_limits_caching.requirements[id] == true

# Fail closed: an unattested recommendation is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CIS MCP %s: %s — not met", [id, m.title])
}

default section_compliant := false

section_compliant if count(violation) == 0

compliance_report := {
	"section": 10,
	"area_name": "Resource Limits and Caching",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": section_compliant,
}
