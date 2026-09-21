package cjis.physical_protection_test

import rego.v1

import data.cjis.physical_protection

# Build an input that attests every requirement as true.
all_true := {"cjis": {"physical_protection": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in physical_protection.requirements}
}

# Empty input -> every requirement fires as a violation and the area is not compliant.
test_empty_input_all_fire if {
	count(physical_protection.violation) == count(physical_protection.requirements) with input as {}
	count(physical_protection.violation) > 0 with input as {}
	not physical_protection.area_compliant with input as {}
}

# Fully attested -> no violations and the area is compliant.
test_all_attested_compliant if {
	count(physical_protection.violation) == 0 with input as all_true
	physical_protection.area_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := object.union(all_true, {"cjis": {"physical_protection": {"requirements": object.union(all_true.cjis.physical_protection.requirements, {"PP-4": false})}}})
	count(physical_protection.violation) == 1 with input as broken
	some msg in physical_protection.violation with input as broken
	contains(msg, "PP-4") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := physical_protection.compliance_report with input as {}
	report.policy_area == 9
	report.area_name == "Physical Protection"
	report.requirements_evaluated == count(physical_protection.requirements)
	report.violation_count == count(physical_protection.requirements)
	report.compliant == false
}
