package irs_1075.disposal_test

import rego.v1

import data.irs_1075.disposal

# Build an input that attests every requirement as true.
all_true := {"irs_1075": {"disposal": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in disposal.requirements}
}

# Empty input -> every requirement fires as a violation and the area is not compliant.
test_empty_input_all_fire if {
	count(disposal.violation) == count(disposal.requirements) with input as {}
	count(disposal.violation) > 0 with input as {}
	not disposal.area_compliant with input as {}
}

# Fully attested -> no violations and the area is compliant.
test_all_attested_compliant if {
	count(disposal.violation) == 0 with input as all_true
	disposal.area_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := object.union(all_true, {"irs_1075": {"disposal": {"requirements": object.union(all_true.irs_1075.disposal.requirements, {"DS-3": false})}}})
	count(disposal.violation) == 1 with input as broken
	some msg in disposal.violation with input as broken
	contains(msg, "DS-3") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := disposal.compliance_report with input as {}
	report.section == "8"
	report.area_name == "Disposal"
	report.requirements_evaluated == count(disposal.requirements)
	report.violation_count == count(disposal.requirements)
	report.compliant == false
}
