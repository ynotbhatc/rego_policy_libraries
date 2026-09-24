package cis_mcp_server.client_host_config

import rego.v1

# CIS MCP Server Benchmark v1.0.0 — Section 4: Client (Host) Configuration.
# Coverage note: implemented from the recommendation set verifiable in public
# sources (the Astrix CIS-MCP-Benchmark-Prober project's published check
# documentation, 2026-09) — 46 of the benchmark's 55 recommendations across 7
# of its 10 sections. Sections 6 (Data Protection and Privacy), 8 (Supply
# Chain Security), and 9 (Isolation and Execution Safety) await the benchmark
# PDF and are NOT implemented; the orchestrator states this coverage
# explicitly. Do not present this module set as full-benchmark coverage.
requirements := {
	"4.1.1": {"section": 4, "level": "unspecified", "title": "Tool invocation requires per-tool consent or a pre-approved allowlist"},
	"4.1.2": {"section": 4, "level": "unspecified", "title": "Server definitions are project-scoped"},
	"4.1.3": {"section": 4, "level": "unspecified", "title": "Elicitation responses require consent and are redacted"},
	"4.1.4": {"section": 4, "level": "unspecified", "title": "Sampling requests require consent and are redacted"},
	"4.1.5": {"section": 4, "level": "unspecified", "title": "Human denial of tool invocations is honored and recorded"},
	"4.2.1": {"section": 4, "level": "unspecified", "title": "Filesystem scope available to servers is restricted"},
	"4.2.2": {"section": 4, "level": "unspecified", "title": "The stdio subprocess environment is restricted"},
	"4.2.3": {"section": 4, "level": "unspecified", "title": "Untrusted Resource URIs are not dereferenced directly by the host"},
	"4.3.1": {"section": 4, "level": "unspecified", "title": "MCP Apps are sandboxed with a Content Security Policy"},
	"4.3.2": {"section": 4, "level": "unspecified", "title": "MCP Apps permissions are constrained and their activity logged"},
}

attested(id) if input.cis_mcp_server.client_host_config.requirements[id] == true

# Fail closed: an unattested recommendation is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CIS MCP %s: %s — not met", [id, m.title])
}

default section_compliant := false

section_compliant if count(violation) == 0

compliance_report := {
	"section": 4,
	"area_name": "Client (Host) Configuration",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": section_compliant,
}
