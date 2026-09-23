package irs_1075.computer_security_test

import rego.v1

import data.irs_1075.computer_security

# Build an input that attests every requirement as true.
all_true := {"irs_1075": {"computer_security": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in computer_security.requirements}
}

# Empty input -> every requirement fires as a violation and the area is not compliant.
test_empty_input_all_fire if {
	count(computer_security.violation) == count(computer_security.requirements) with input as {}
	count(computer_security.violation) > 0 with input as {}
	not computer_security.area_compliant with input as {}
}

# Fully attested -> no violations and the area is compliant.
test_all_attested_compliant if {
	count(computer_security.violation) == 0 with input as all_true
	computer_security.area_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := object.union(all_true, {"irs_1075": {"computer_security": {"requirements": object.union(all_true.irs_1075.computer_security.requirements, {"CS-11": false})}}})
	count(computer_security.violation) == 1 with input as broken
	some msg in computer_security.violation with input as broken
	contains(msg, "CS-11") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := computer_security.compliance_report with input as {}
	report.section == "9"
	report.area_name == "Computer Security"
	report.requirements_evaluated == count(computer_security.requirements)
	report.violation_count == count(computer_security.requirements)
	report.compliant == false
}
