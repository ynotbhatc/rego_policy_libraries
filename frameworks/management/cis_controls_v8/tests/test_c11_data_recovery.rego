package cis_controls_v8.c11_test

import rego.v1

import data.cis_controls_v8.c11

all_true := {"cis_controls": {"safeguards": {
	"11.1": true,
	"11.2": true,
	"11.3": true,
	"11.4": true,
	"11.5": true,
}}}

test_empty_input_all_fire if {
	count(c11.violation) == count(c11.safeguards) with input as {}
	not c11.control_compliant with input as {}
}

test_all_attested_compliant if {
	count(c11.violation) == 0 with input as all_true
	c11.control_compliant with input as all_true
}

test_single_flip_one_violation if {
	inp := object.union(all_true, {"cis_controls": {"safeguards": {"11.3": false}}})
	count(c11.violation) == 1 with input as inp
	some msg in c11.violation with input as inp
	contains(msg, "11.3") with input as inp
}

test_compliance_report_populated if {
	rep := c11.compliance_report with input as {}
	rep.control == 11
	rep.safeguards_evaluated == count(c11.safeguards)
	rep.violation_count == count(c11.safeguards)
	rep.compliant == false
}
