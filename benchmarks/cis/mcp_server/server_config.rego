package cis_mcp_server.server_config

import rego.v1

# CIS MCP Server Benchmark v1.0.0 — Section 5: Server Configuration.
# Coverage note: implemented from the recommendation set verifiable in public
# sources (the Astrix CIS-MCP-Benchmark-Prober project's published check
# documentation, 2026-09) — 46 of the benchmark's 55 recommendations across 7
# of its 10 sections. Sections 6 (Data Protection and Privacy), 8 (Supply
# Chain Security), and 9 (Isolation and Execution Safety) await the benchmark
# PDF and are NOT implemented; the orchestrator states this coverage
# explicitly. Do not present this module set as full-benchmark coverage.
requirements := {
	"5.1.1": {"section": 5, "level": "L1", "title": "Tool schemas and argument types are validated"},
	"5.1.2": {"section": 5, "level": "L1", "title": "Resource templates declare explicit URI patterns and MIME types"},
	"5.1.3": {"section": 5, "level": "L1", "title": "Prompt templates declare and validate their arguments"},
	"5.2.1": {"section": 5, "level": "L2", "title": "listChanged notifications are rate limited"},
	"5.2.2": {"section": 5, "level": "L1", "title": "Sessions are not used as authentication"},
	"5.2.3": {"section": 5, "level": "L1", "title": "Legacy Streamable HTTP session and stream resumption surfaces are disabled"},
	"5.3.1": {"section": 5, "level": "L1", "title": "Logs are separated from protocol output in stdio mode"},
	"5.4.1": {"section": 5, "level": "L1", "title": "Path traversal and arbitrary filesystem access are prevented"},
	"5.5.1": {"section": 5, "level": "unspecified", "title": "Task authorization is enforced across identities"},
	"5.6.1": {"section": 5, "level": "L2", "title": "Idempotency keys are required for side-effecting tools"},
}

attested(id) if input.cis_mcp_server.server_config.requirements[id] == true

# Fail closed: an unattested recommendation is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CIS MCP %s: %s — not met", [id, m.title])
}

default section_compliant := false

section_compliant if count(violation) == 0

compliance_report := {
	"section": 5,
	"area_name": "Server Configuration",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": section_compliant,
}
