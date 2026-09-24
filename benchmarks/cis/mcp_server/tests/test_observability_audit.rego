package cis_mcp_server.observability_audit_test

import rego.v1

import data.cis_mcp_server.observability_audit

# Build an input that attests every requirement as true.
all_true := {"cis_mcp_server": {"observability_audit": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in observability_audit.requirements}
}

# Empty input -> every requirement fires as a violation and the section is not compliant.
test_empty_input_all_fire if {
	count(observability_audit.violation) == count(observability_audit.requirements) with input as {}
	count(observability_audit.violation) > 0 with input as {}
	not observability_audit.section_compliant with input as {}
}

# Fully attested -> no violations and the section is compliant.
test_all_attested_compliant if {
	count(observability_audit.violation) == 0 with input as all_true
	observability_audit.section_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.cis_mcp_server.observability_audit.requirements, {"7.1.2": false})
	broken := object.union(all_true, {"cis_mcp_server": {"observability_audit": {"requirements": flipped}}})
	count(observability_audit.violation) == 1 with input as broken
	some msg in observability_audit.violation with input as broken
	contains(msg, "7.1.2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := observability_audit.compliance_report with input as {}
	report.section == 7
	report.area_name == "Observability and Audit"
	report.requirements_evaluated == count(observability_audit.requirements)
	report.violation_count == count(observability_audit.requirements)
	report.compliant == false
}
