package cis_mcp_server.client_host_config_test

import rego.v1

import data.cis_mcp_server.client_host_config

# Build an input that attests every requirement as true.
all_true := {"cis_mcp_server": {"client_host_config": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in client_host_config.requirements}
}

# Empty input -> every requirement fires as a violation and the section is not compliant.
test_empty_input_all_fire if {
	count(client_host_config.violation) == count(client_host_config.requirements) with input as {}
	count(client_host_config.violation) > 0 with input as {}
	not client_host_config.section_compliant with input as {}
}

# Fully attested -> no violations and the section is compliant.
test_all_attested_compliant if {
	count(client_host_config.violation) == 0 with input as all_true
	client_host_config.section_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.cis_mcp_server.client_host_config.requirements, {"4.1.2": false})
	broken := object.union(all_true, {"cis_mcp_server": {"client_host_config": {"requirements": flipped}}})
	count(client_host_config.violation) == 1 with input as broken
	some msg in client_host_config.violation with input as broken
	contains(msg, "4.1.2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := client_host_config.compliance_report with input as {}
	report.section == 4
	report.area_name == "Client (Host) Configuration"
	report.requirements_evaluated == count(client_host_config.requirements)
	report.violation_count == count(client_host_config.requirements)
	report.compliant == false
}
