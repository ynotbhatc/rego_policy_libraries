# CIS MCP Server Benchmark v1.0.0 — master orchestrator
#
# Aggregates the implemented sections of the CIS MCP Server Benchmark
# (released 2026-09) into one fail-closed compliance report with per-section
# and per-level (L1/L2) rollups.
#
# COVERAGE — stated, never implied: 46 of 55 recommendations across 7 of 10
# sections, implemented from the recommendation set verifiable in public
# sources (the Astrix CIS-MCP-Benchmark-Prober published check docs).
# Sections 6 (Data Protection and Privacy), 8 (Supply Chain Security) and
# 9 (Isolation and Execution Safety) are NOT implemented pending the
# benchmark PDF; the report carries this in its coverage object.
#
# Entry point: data.cis_mcp_server.main.compliance_report

package cis_mcp_server.main

import rego.v1

import data.cis_mcp_server.authn_authz
import data.cis_mcp_server.client_host_config
import data.cis_mcp_server.governance_versioning
import data.cis_mcp_server.observability_audit
import data.cis_mcp_server.resource_limits_caching
import data.cis_mcp_server.server_config
import data.cis_mcp_server.transport_connectivity

# Per-section reports, in benchmark section order.
section_reports := [
	governance_versioning.compliance_report,
	transport_connectivity.compliance_report,
	authn_authz.compliance_report,
	client_host_config.compliance_report,
	server_config.compliance_report,
	observability_audit.compliance_report,
	resource_limits_caching.compliance_report,
]

all_violations := [v | some r in section_reports; some v in r.violations]

# Attestation object for a section, defaulted to {} so the report is robust
# to entirely-absent input (the standard bare `opa eval` verify command) and
# to a malformed non-object `requirements` value, which would otherwise make
# object.get undefined and silently drop the section's ids from _all.
default _attest(_) := {}

_attest(section) := req if {
	req := input.cis_mcp_server[section].requirements
	is_object(req)
}

_specs := [
	{"key": "governance_versioning", "req": governance_versioning.requirements},
	{"key": "transport_connectivity", "req": transport_connectivity.requirements},
	{"key": "authn_authz", "req": authn_authz.requirements},
	{"key": "client_host_config", "req": client_host_config.requirements},
	{"key": "server_config", "req": server_config.requirements},
	{"key": "observability_audit", "req": observability_audit.requirements},
	{"key": "resource_limits_caching", "req": resource_limits_caching.requirements},
]

# id -> {level, met}. Recommendation ids are unique across sections (the
# benchmark numbers them globally).
_all[id] := {"level": m.level, "met": object.get(_attest(spec.key), id, false) == true} if {
	some spec in _specs
	some id, m in spec.req
}

total_requirements := count(_all)

requirements_met := count([id | some id, c in _all; c.met])

# Level rollups. Requirements whose level the public sources did not state
# carry level "unspecified" and are excluded from the L1/L2 floors (but
# always count toward overall compliance).
l1_total := count([id | some id, c in _all; c.level == "L1"])

l1_met := count([id | some id, c in _all; c.level == "L1"; c.met])

l2_total := count([id | some id, c in _all; c.level == "L2"])

l2_met := count([id | some id, c in _all; c.level == "L2"; c.met])

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
		"missing_sections": {
			"6": "Data Protection and Privacy",
			"8": "Supply Chain Security",
			"9": "Isolation and Execution Safety",
		},
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
