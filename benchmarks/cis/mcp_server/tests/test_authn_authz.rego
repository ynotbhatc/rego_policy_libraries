package cis_mcp_server.authn_authz_test

import rego.v1

import data.cis_mcp_server.authn_authz

# Build an input that attests every requirement as true.
all_true := {"cis_mcp_server": {"authn_authz": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in authn_authz.requirements}
}

# Empty input -> every requirement fires as a violation and the section is not compliant.
test_empty_input_all_fire if {
	count(authn_authz.violation) == count(authn_authz.requirements) with input as {}
	count(authn_authz.violation) > 0 with input as {}
	not authn_authz.section_compliant with input as {}
}

# Fully attested -> no violations and the section is compliant.
test_all_attested_compliant if {
	count(authn_authz.violation) == 0 with input as all_true
	authn_authz.section_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.cis_mcp_server.authn_authz.requirements, {"3.1.2": false})
	broken := object.union(all_true, {"cis_mcp_server": {"authn_authz": {"requirements": flipped}}})
	count(authn_authz.violation) == 1 with input as broken
	some msg in authn_authz.violation with input as broken
	contains(msg, "3.1.2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := authn_authz.compliance_report with input as {}
	report.section == 3
	report.area_name == "Authentication and Authorization"
	report.requirements_evaluated == count(authn_authz.requirements)
	report.violation_count == count(authn_authz.requirements)
	report.compliant == false
}
