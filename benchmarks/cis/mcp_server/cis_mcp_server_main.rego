# CIS MCP Server Benchmark v1.0.0 — master orchestrator
#
# Aggregates all 10 sections of the CIS MCP Server Benchmark v1.0.0 into one
# fail-closed compliance report with per-section and per-level (L1/L2) rollups.
#
# COVERAGE: 55 of 55 recommendations across 10 of 10 sections. Ids, titles,
# levels (Level 1 / Level 2 profile sheets) and Automated/Manual status come
# from the official CIS workbook. Automated recommendations are judged from
# collected evidence (input.cis_mcp_server.<section>.evidence); Manual ones
# from attestation (input.cis_mcp_server.<section>.requirements).
#
# Entry point: data.cis_mcp_server.main.compliance_report

# METADATA
# title: "CIS MCP Server Benchmark v1.0.0 — master orchestrator"
# custom:
#   class: security
#   framework: cis_mcp_server
#   source: cis
#   domains: [ai, mcp]
#   coverage:
#     checks: 0
#     cited: 0
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_mcp_server.main

import rego.v1

import data.cis_mcp_server.authn_authz
import data.cis_mcp_server.client_host_config
import data.cis_mcp_server.data_protection_privacy
import data.cis_mcp_server.governance_versioning
import data.cis_mcp_server.isolation_execution_safety
import data.cis_mcp_server.observability_audit
import data.cis_mcp_server.resource_limits_caching
import data.cis_mcp_server.server_config
import data.cis_mcp_server.supply_chain_security
import data.cis_mcp_server.transport_connectivity

# Per-section reports, in benchmark section order.
section_reports := [
	governance_versioning.compliance_report,
	transport_connectivity.compliance_report,
	authn_authz.compliance_report,
	client_host_config.compliance_report,
	server_config.compliance_report,
	data_protection_privacy.compliance_report,
	observability_audit.compliance_report,
	supply_chain_security.compliance_report,
	isolation_execution_safety.compliance_report,
	resource_limits_caching.compliance_report,
]

all_violations := [v | some r in section_reports; some v in r.violations]

# Each section module decides which of its recommendations are met (Manual:
# attested; Automated: evidence present and every check passing).
_specs := [
	{"req": governance_versioning.requirements, "met": governance_versioning.met},
	{"req": transport_connectivity.requirements, "met": transport_connectivity.met},
	{"req": authn_authz.requirements, "met": authn_authz.met},
	{"req": client_host_config.requirements, "met": client_host_config.met},
	{"req": server_config.requirements, "met": server_config.met},
	{"req": data_protection_privacy.requirements, "met": data_protection_privacy.met},
	{"req": observability_audit.requirements, "met": observability_audit.met},
	{"req": supply_chain_security.requirements, "met": supply_chain_security.met},
	{"req": isolation_execution_safety.requirements, "met": isolation_execution_safety.met},
	{"req": resource_limits_caching.requirements, "met": resource_limits_caching.met},
]

# id -> {level, met}. Recommendation ids are unique across sections (the
# benchmark numbers them globally).
_all[id] := {"level": m.level, "met": id in spec.met} if {
	some spec in _specs
	some id, m in spec.req
}

total_requirements := count(_all)

requirements_met := count([id | some id; c := _all[id]; c.met])

# Level rollups. Every recommendation is Level 1 or Level 2 per the workbook.
l1_total := count([id | some id; c := _all[id]; c.level == "L1"])

l1_met := count([id | some id; c := _all[id]; c.level == "L1"; c.met])

l2_total := count([id | some id; c := _all[id]; c.level == "L2"])

l2_met := count([id | some id; c := _all[id]; c.level == "L2"; c.met])

default l1_compliant := false

l1_compliant if {
	l1_total > 0
	l1_met == l1_total
}

# Per-section rollup, keyed by section name.
sections[name] := {
	"section": r.section,
	"requirements": r.requirements_evaluated,
	"gaps": r.violation_count,
	"compliant": r.compliant,
} if {
	some r in section_reports
	name := r.area_name
}

default compliant := false

compliant if count(all_violations) == 0

compliance_report := {
	"framework": "CIS MCP Server Benchmark v1.0.0",
	"reference": "CIS MCP Server Benchmark v1.0.0 (2026-09)",
	"coverage": {
		"sections_implemented": count(section_reports),
		"sections_total": 10,
		"recommendations_implemented": total_requirements,
		"recommendations_total": 55,
		"missing_sections": {},
	},
	"sections_evaluated": count(section_reports),
	"total_requirements": total_requirements,
	"requirements_met": requirements_met,
	"l1": {"total": l1_total, "met": l1_met, "compliant": l1_compliant},
	"l2": {"total": l2_total, "met": l2_met},
	"sections": sections,
	"violations": all_violations,
	"violation_count": count(all_violations),
	"compliant": compliant,
}
