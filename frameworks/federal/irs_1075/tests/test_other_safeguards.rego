package irs_1075.other_safeguards_test

import rego.v1

import data.irs_1075.other_safeguards

# Build an input that attests every requirement as true.
all_true := {"irs_1075": {"other_safeguards": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in other_safeguards.requirements}
}

# Empty input -> every requirement fires as a violation and the area is not compliant.
test_empty_input_all_fire if {
	count(other_safeguards.violation) == count(other_safeguards.requirements) with input as {}
	count(other_safeguards.violation) > 0 with input as {}
	not other_safeguards.area_compliant with input as {}
}

# Fully attested -> no violations and the area is compliant.
test_all_attested_compliant if {
	count(other_safeguards.violation) == 0 with input as all_true
	other_safeguards.area_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := object.union(all_true, {"irs_1075": {"other_safeguards": {"requirements": object.union(all_true.irs_1075.other_safeguards.requirements, {"OS-2": false})}}})
	count(other_safeguards.violation) == 1 with input as broken
	some msg in other_safeguards.violation with input as broken
	contains(msg, "OS-2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := other_safeguards.compliance_report with input as {}
	report.section == "6"
	report.area_name == "Other Safeguards"
	report.requirements_evaluated == count(other_safeguards.requirements)
	report.violation_count == count(other_safeguards.requirements)
	report.compliant == false
}
