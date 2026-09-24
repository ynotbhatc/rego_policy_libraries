package cis_mcp_server.governance_versioning

import rego.v1

# CIS MCP Server Benchmark v1.0.0 — Section 1: Governance and Versioning.
# Coverage note: implemented from the recommendation set verifiable in public
# sources (the Astrix CIS-MCP-Benchmark-Prober project's published check
# documentation, 2026-09) — 46 of the benchmark's 55 recommendations across 7
# of its 10 sections. Sections 6 (Data Protection and Privacy), 8 (Supply
# Chain Security), and 9 (Isolation and Execution Safety) await the benchmark
# PDF and are NOT implemented; the orchestrator states this coverage
# explicitly. Do not present this module set as full-benchmark coverage.
requirements := {
	"1.1": {"section": 1, "level": "L1", "title": "Served protocol revisions are pinned and malformed version assertions are rejected"},
	"1.2": {"section": 1, "level": "L1", "title": "Advertised capability configuration matches the recorded baseline"},
	"1.3": {"section": 1, "level": "L2", "title": "A capability advertised beyond the baseline is denied until re-approved"},
	"1.4": {"section": 1, "level": "L1", "title": "Server name and version match the recorded identity"},
}

attested(id) if input.cis_mcp_server.governance_versioning.requirements[id] == true

# Fail closed: an unattested recommendation is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CIS MCP %s: %s — not met", [id, m.title])
}

default section_compliant := false

section_compliant if count(violation) == 0

compliance_report := {
	"section": 1,
	"area_name": "Governance and Versioning",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": section_compliant,
}
