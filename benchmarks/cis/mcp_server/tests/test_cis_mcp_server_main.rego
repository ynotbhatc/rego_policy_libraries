# Tests for the CIS MCP Server Benchmark master orchestrator.
package cis_mcp_server.main_test

import rego.v1

import data.cis_mcp_server.main

# Each section test package's compliant fixture (Manual attested, Automated with passing evidence).
_fixtures := {
	"governance_versioning": data.cis_mcp_server.governance_versioning_test.full_input,
	"transport_connectivity": data.cis_mcp_server.transport_connectivity_test.full_input,
	"authn_authz": data.cis_mcp_server.authn_authz_test.full_input,
	"client_host_config": data.cis_mcp_server.client_host_config_test.full_input,
	"server_config": data.cis_mcp_server.server_config_test.full_input,
	"data_protection_privacy": data.cis_mcp_server.data_protection_privacy_test.full_input,
	"observability_audit": data.cis_mcp_server.observability_audit_test.full_input,
	"supply_chain_security": data.cis_mcp_server.supply_chain_security_test.full_input,
	"isolation_execution_safety": data.cis_mcp_server.isolation_execution_safety_test.full_input,
	"resource_limits_caching": data.cis_mcp_server.resource_limits_caching_test.full_input,
}

# Fully compliant input for every section (name kept from the pre-v1.0.0 tests).
all_true := {"cis_mcp_server": {section: f.cis_mcp_server[section] | some section, f in _fixtures}}

test_empty_input_all_gaps if {
	r := main.compliance_report with input as {}
	r.sections_evaluated == 10
	count(r.sections) == 10
	r.total_requirements == 55
	r.violation_count == r.total_requirements
	r.requirements_met == 0
	r.compliant == false
	r.l1.compliant == false
}

test_coverage_is_stated_honestly if {
	r := main.compliance_report with input as {}
	r.coverage.sections_implemented == 10
	r.coverage.sections_total == 10
	r.coverage.recommendations_implemented == 55
	r.coverage.recommendations_total == 55
	count(r.coverage.missing_sections) == 0
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
	r.total_requirements == 55
	r.requirements_met == 0
	r.compliant == false
}

# Truthy-but-not-true attestation is unmet on both counter paths.
# (2.2 is Automated in v1.0.0, so the Manual 2.1 is used.)
test_truthy_attestation_not_met if {
	truthy := json.patch(all_true, [{"op": "replace", "path": "/cis_mcp_server/transport_connectivity/requirements/2.1", "value": "yes"}])
	r := main.compliance_report with input as truthy
	r.requirements_met == r.total_requirements - 1
	r.violation_count == 1
	r.compliant == false
}

# 2.5 is Automated in v1.0.0: withdrawing its evidence is the gap.
test_single_section_gap_propagates if {
	dropped := json.patch(all_true, [{"op": "remove", "path": "/cis_mcp_server/transport_connectivity/evidence/origin"}])
	r := main.compliance_report with input as dropped
	r.violation_count == 1
	r.requirements_met == r.total_requirements - 1
	r.compliant == false
	r.sections["Transport and Connectivity"].compliant == false
}

# Workbook profile split: 39 Level 1 and 16 Level 2 recommendations.
test_level_totals_match_workbook if {
	r := main.compliance_report with input as {}
	r.l1.total == 39
	r.l2.total == 16
	r.l1.total + r.l2.total == r.total_requirements
}

# Sections 6, 8 and 9 are wired into the report.
test_new_sections_reported if {
	r := main.compliance_report with input as all_true
	r.sections["Data Protection and Privacy"] == {"section": 6, "requirements": 3, "gaps": 0, "compliant": true}
	r.sections["Supply Chain Security"] == {"section": 8, "requirements": 3, "gaps": 0, "compliant": true}
	r.sections["Isolation and Execution Safety"] == {"section": 9, "requirements": 3, "gaps": 0, "compliant": true}
}

# A gap in a new section propagates to the totals.
test_new_section_gap_propagates if {
	dropped := json.patch(all_true, [{"op": "remove", "path": "/cis_mcp_server/isolation_execution_safety/evidence/confinement"}])
	r := main.compliance_report with input as dropped
	r.violation_count == 1
	r.requirements_met == r.total_requirements - 1
	r.l1.compliant == false
	r.compliant == false
	r.sections["Isolation and Execution Safety"].gaps == 1
}

# Attesting every id without collecting evidence leaves all 24 Automated recommendations unmet.
test_attestation_alone_does_not_meet_automated if {
	attest_all := {"cis_mcp_server": {section: {"requirements": object.union(
		{id: true | some id, _ in data.cis_mcp_server[section].requirements},
		f.cis_mcp_server[section].requirements,
	)} |
		some section, f in _fixtures
	}}
	r := main.compliance_report with input as attest_all
	r.requirements_met == 31
	r.violation_count == 24
	r.compliant == false
}
