package cis_mcp_server.transport_connectivity_test

import rego.v1

import data.cis_mcp_server.transport_connectivity

# Build an input that attests every requirement as true.
all_true := {"cis_mcp_server": {"transport_connectivity": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in transport_connectivity.requirements}
}

# Empty input -> every requirement fires as a violation and the section is not compliant.
test_empty_input_all_fire if {
	count(transport_connectivity.violation) == count(transport_connectivity.requirements) with input as {}
	count(transport_connectivity.violation) > 0 with input as {}
	not transport_connectivity.section_compliant with input as {}
}

# Fully attested -> no violations and the section is compliant.
test_all_attested_compliant if {
	count(transport_connectivity.violation) == 0 with input as all_true
	transport_connectivity.section_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.cis_mcp_server.transport_connectivity.requirements, {"2.2": false})
	broken := object.union(all_true, {"cis_mcp_server": {"transport_connectivity": {"requirements": flipped}}})
	count(transport_connectivity.violation) == 1 with input as broken
	some msg in transport_connectivity.violation with input as broken
	contains(msg, "2.2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := transport_connectivity.compliance_report with input as {}
	report.section == 2
	report.area_name == "Transport and Connectivity"
	report.requirements_evaluated == count(transport_connectivity.requirements)
	report.violation_count == count(transport_connectivity.requirements)
	report.compliant == false
}
