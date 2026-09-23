package irs_1075.reporting_test

import rego.v1

import data.irs_1075.reporting

# Build an input that attests every requirement as true.
all_true := {"irs_1075": {"reporting": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in reporting.requirements}
}

# Empty input -> every requirement fires as a violation and the area is not compliant.
test_empty_input_all_fire if {
	count(reporting.violation) == count(reporting.requirements) with input as {}
	count(reporting.violation) > 0 with input as {}
	not reporting.area_compliant with input as {}
}

# Fully attested -> no violations and the area is compliant.
test_all_attested_compliant if {
	count(reporting.violation) == 0 with input as all_true
	reporting.area_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := object.union(all_true, {"irs_1075": {"reporting": {"requirements": object.union(all_true.irs_1075.reporting.requirements, {"RP-3": false})}}})
	count(reporting.violation) == 1 with input as broken
	some msg in reporting.violation with input as broken
	contains(msg, "RP-3") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := reporting.compliance_report with input as {}
	report.section == "7"
	report.area_name == "Reporting"
	report.requirements_evaluated == count(reporting.requirements)
	report.violation_count == count(reporting.requirements)
	report.compliant == false
}
