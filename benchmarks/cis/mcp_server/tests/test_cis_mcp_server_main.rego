# Tests for the CIS MCP Server Benchmark master orchestrator.
package cis_mcp_server.main_test

import rego.v1

import data.cis_mcp_server.main

_sections := {
	"governance_versioning": data.cis_mcp_server.governance_versioning.requirements,
	"transport_connectivity": data.cis_mcp_server.transport_connectivity.requirements,
	"authn_authz": data.cis_mcp_server.authn_authz.requirements,
	"client_host_config": data.cis_mcp_server.client_host_config.requirements,
	"server_config": data.cis_mcp_server.server_config.requirements,
	"observability_audit": data.cis_mcp_server.observability_audit.requirements,
	"resource_limits_caching": data.cis_mcp_server.resource_limits_caching.requirements,
}

# Fully-attested input built from every section's own requirement set.
all_true := {"cis_mcp_server": {section: {"requirements": {id: true | some id, _ in reqs}} |
	some section, reqs in _sections
}}

test_empty_input_all_gaps if {
	r := main.compliance_report with input as {}
	r.sections_evaluated == 7
	count(r.sections) == 7
	r.total_requirements == 46
	r.violation_count == r.total_requirements
	r.requirements_met == 0
	r.compliant == false
	r.l1.compliant == false
}

test_coverage_is_stated_honestly if {
	r := main.compliance_report with input as {}
	r.coverage.sections_implemented == 7
	r.coverage.sections_total == 10
	r.coverage.recommendations_implemented == 46
	r.coverage.recommendations_total == 55
	count(r.coverage.missing_sections) == 3
}

test_fully_attested_is_compliant if {
	r := main.compliance_report with input as all_true
	r.violation_count == 0
	r.compliant == true
	r.requirements_met == r.total_requirements
	r.l1.compliant == true
	r.l1.met == r.l1.total
}

# All L1 met but one L2 gap -> l1_compliant true, overall compliant false.
test_l1_floor_independent_of_l2 if {
	dropped := json.patch(all_true, [{"op": "remove", "path": "/cis_mcp_server/authn_authz/requirements/3.3.4"}])
	r := main.compliance_report with input as dropped
	r.l1.compliant == true
	r.compliant == false
	r.violation_count == 1
}

# A non-object requirements payload must not shrink total_requirements.
test_malformed_attestation_keeps_totals if {
	malformed := {"cis_mcp_server": {"authn_authz": {"requirements": "all attested"}}}
	r := main.compliance_report with input as malformed
	r.total_requirements == 46
	r.requirements_met == 0
	r.compliant == false
}

# Truthy-but-not-true attestation is unmet on both counter paths.
test_truthy_attestation_not_met if {
	truthy := json.patch(all_true, [{"op": "replace", "path": "/cis_mcp_server/transport_connectivity/requirements/2.2", "value": "yes"}])
	r := main.compliance_report with input as truthy
	r.requirements_met == r.total_requirements - 1
	r.violation_count == 1
	r.compliant == false
}

test_single_section_gap_propagates if {
	dropped := json.patch(all_true, [{"op": "remove", "path": "/cis_mcp_server/transport_connectivity/requirements/2.5"}])
	r := main.compliance_report with input as dropped
	r.violation_count == 1
	r.requirements_met == r.total_requirements - 1
	r.compliant == false
	r.sections["Transport and Connectivity"].compliant == false
}
