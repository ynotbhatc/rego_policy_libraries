package irs_1075.recordkeeping_test

import rego.v1

import data.irs_1075.recordkeeping

# Build an input that attests every requirement as true.
all_true := {"irs_1075": {"recordkeeping": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in recordkeeping.requirements}
}

# Empty input -> every requirement fires as a violation and the area is not compliant.
test_empty_input_all_fire if {
	count(recordkeeping.violation) == count(recordkeeping.requirements) with input as {}
	count(recordkeeping.violation) > 0 with input as {}
	not recordkeeping.area_compliant with input as {}
}

# Fully attested -> no violations and the area is compliant.
test_all_attested_compliant if {
	count(recordkeeping.violation) == 0 with input as all_true
	recordkeeping.area_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := object.union(all_true, {"irs_1075": {"recordkeeping": {"requirements": object.union(all_true.irs_1075.recordkeeping.requirements, {"RK-3": false})}}})
	count(recordkeeping.violation) == 1 with input as broken
	some msg in recordkeeping.violation with input as broken
	contains(msg, "RK-3") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := recordkeeping.compliance_report with input as {}
	report.section == "3"
	report.area_name == "Recordkeeping"
	report.requirements_evaluated == count(recordkeeping.requirements)
	report.violation_count == count(recordkeeping.requirements)
	report.compliant == false
}
