package cis_controls_v8.c15_test

import rego.v1

import data.cis_controls_v8.c15

# All safeguard IDs, mapped to true (fully attested input).
all_attested := {"cis_controls": {"safeguards": {id: true | some id, _ in c15.safeguards}}}

test_empty_input_all_fire if {
	count(c15.violation) == count(c15.safeguards) with input as {}
	not c15.control_compliant with input as {}
}

test_all_attested_no_violations if {
	count(c15.violation) == 0 with input as all_attested
	c15.control_compliant with input as all_attested
}

test_single_flip_one_violation if {
	flipped := object.union(all_attested, {"cis_controls": {"safeguards": object.union(all_attested.cis_controls.safeguards, {"15.1": false})}})
	count(c15.violation) == 1 with input as flipped
	not c15.control_compliant with input as flipped
	some msg in c15.violation with input as flipped
	contains(msg, "15.1")
}

test_report_populated_on_empty_input if {
	report := c15.compliance_report with input as {}
	report.control == 15
	report.name == "Service Provider Management"
	report.safeguards_evaluated == count(c15.safeguards)
	report.violation_count == count(c15.safeguards)
	report.compliant == false
}
