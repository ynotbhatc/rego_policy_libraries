package cis_controls_v8.c14_test

import rego.v1

import data.cis_controls_v8.c14

# All safeguard IDs, mapped to true (fully attested input).
all_attested := {"cis_controls": {"safeguards": {id: true | some id, _ in c14.safeguards}}}

test_empty_input_all_fire if {
	count(c14.violation) == count(c14.safeguards) with input as {}
	not c14.control_compliant with input as {}
}

test_all_attested_no_violations if {
	count(c14.violation) == 0 with input as all_attested
	c14.control_compliant with input as all_attested
}

test_single_flip_one_violation if {
	flipped := object.union(all_attested, {"cis_controls": {"safeguards": object.union(all_attested.cis_controls.safeguards, {"14.9": false})}})
	count(c14.violation) == 1 with input as flipped
	not c14.control_compliant with input as flipped
	some msg in c14.violation with input as flipped
	contains(msg, "14.9")
}

test_report_populated_on_empty_input if {
	report := c14.compliance_report with input as {}
	report.control == 14
	report.name == "Security Awareness and Skills Training"
	report.safeguards_evaluated == count(c14.safeguards)
	report.violation_count == count(c14.safeguards)
	report.compliant == false
}
