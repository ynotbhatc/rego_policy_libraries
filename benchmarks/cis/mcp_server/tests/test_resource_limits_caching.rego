package cis_mcp_server.resource_limits_caching_test

import rego.v1

import data.cis_mcp_server.resource_limits_caching

# Build an input that attests every requirement as true.
all_true := {"cis_mcp_server": {"resource_limits_caching": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in resource_limits_caching.requirements}
}

# Empty input -> every requirement fires as a violation and the section is not compliant.
test_empty_input_all_fire if {
	count(resource_limits_caching.violation) == count(resource_limits_caching.requirements) with input as {}
	count(resource_limits_caching.violation) > 0 with input as {}
	not resource_limits_caching.section_compliant with input as {}
}

# Fully attested -> no violations and the section is compliant.
test_all_attested_compliant if {
	count(resource_limits_caching.violation) == 0 with input as all_true
	resource_limits_caching.section_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.cis_mcp_server.resource_limits_caching.requirements, {"10.2": false})
	broken := object.union(all_true, {"cis_mcp_server": {"resource_limits_caching": {"requirements": flipped}}})
	count(resource_limits_caching.violation) == 1 with input as broken
	some msg in resource_limits_caching.violation with input as broken
	contains(msg, "10.2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := resource_limits_caching.compliance_report with input as {}
	report.section == 10
	report.area_name == "Resource Limits and Caching"
	report.requirements_evaluated == count(resource_limits_caching.requirements)
	report.violation_count == count(resource_limits_caching.requirements)
	report.compliant == false
}
