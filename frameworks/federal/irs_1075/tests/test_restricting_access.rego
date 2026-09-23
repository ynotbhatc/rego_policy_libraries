package irs_1075.restricting_access_test

import rego.v1

import data.irs_1075.restricting_access

# Build an input that attests every requirement as true.
all_true := {"irs_1075": {"restricting_access": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in restricting_access.requirements}
}

# Empty input -> every requirement fires as a violation and the area is not compliant.
test_empty_input_all_fire if {
	count(restricting_access.violation) == count(restricting_access.requirements) with input as {}
	count(restricting_access.violation) > 0 with input as {}
	not restricting_access.area_compliant with input as {}
}

# Fully attested -> no violations and the area is compliant.
test_all_attested_compliant if {
	count(restricting_access.violation) == 0 with input as all_true
	restricting_access.area_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := object.union(all_true, {"irs_1075": {"restricting_access": {"requirements": object.union(all_true.irs_1075.restricting_access.requirements, {"RA-4": false})}}})
	count(restricting_access.violation) == 1 with input as broken
	some msg in restricting_access.violation with input as broken
	contains(msg, "RA-4") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := restricting_access.compliance_report with input as {}
	report.section == "5"
	report.area_name == "Restricting Access"
	report.requirements_evaluated == count(restricting_access.requirements)
	report.violation_count == count(restricting_access.requirements)
	report.compliant == false
}
