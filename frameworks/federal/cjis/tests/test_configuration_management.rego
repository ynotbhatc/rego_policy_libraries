package cjis.configuration_management_test

import rego.v1

import data.cjis.configuration_management

# Build an input that attests every requirement as true.
all_true := {"cjis": {"configuration_management": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in configuration_management.requirements}
}

# Empty input -> every requirement fires as a violation and the area is not compliant.
test_empty_input_all_fire if {
	count(configuration_management.violation) == count(configuration_management.requirements) with input as {}
	count(configuration_management.violation) > 0 with input as {}
	not configuration_management.area_compliant with input as {}
}

# Fully attested -> no violations and the area is compliant.
test_all_attested_compliant if {
	count(configuration_management.violation) == 0 with input as all_true
	configuration_management.area_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := object.union(all_true, {"cjis": {"configuration_management": {"requirements": object.union(all_true.cjis.configuration_management.requirements, {"CM-3": false})}}})
	count(configuration_management.violation) == 1 with input as broken
	some msg in configuration_management.violation with input as broken
	contains(msg, "CM-3") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := configuration_management.compliance_report with input as {}
	report.policy_area == 7
	report.area_name == "Configuration Management"
	report.requirements_evaluated == count(configuration_management.requirements)
	report.violation_count == count(configuration_management.requirements)
	report.compliant == false
}
