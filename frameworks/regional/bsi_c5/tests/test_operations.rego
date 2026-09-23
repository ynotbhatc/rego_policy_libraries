package bsi_c5.operations_test

import rego.v1

import data.bsi_c5.operations

# Build an input that attests every requirement as true.
all_true := {"bsi_c5": {"operations": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in operations.requirements}
}

# Empty input -> every requirement fires as a violation and the domain is not compliant.
test_empty_input_all_fire if {
	count(operations.violation) == count(operations.requirements) with input as {}
	count(operations.violation) > 0 with input as {}
	not operations.domain_compliant with input as {}
}

# Fully attested -> no violations and the domain is compliant.
test_all_attested_compliant if {
	count(operations.violation) == 0 with input as all_true
	operations.domain_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.bsi_c5.operations.requirements, {"OPS-2": false})
	broken := object.union(all_true, {"bsi_c5": {"operations": {"requirements": flipped}}})
	count(operations.violation) == 1 with input as broken
	some msg in operations.violation with input as broken
	contains(msg, "OPS-2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := operations.compliance_report with input as {}
	report.domain == "OPS"
	report.area_name == "Operations"
	report.requirements_evaluated == count(operations.requirements)
	report.violation_count == count(operations.requirements)
	report.compliant == false
}
