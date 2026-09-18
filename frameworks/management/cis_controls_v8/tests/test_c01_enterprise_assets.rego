package cis_controls_v8.c01_test

import rego.v1

import data.cis_controls_v8.c01

all_true := {"cis_controls": {"safeguards": {
	"1.1": true,
	"1.2": true,
	"1.3": true,
	"1.4": true,
	"1.5": true,
}}}

test_empty_input_all_fire if {
	count(c01.violation) == count(c01.safeguards) with input as {}
	not c01.control_compliant with input as {}
}

test_all_attested_compliant if {
	count(c01.violation) == 0 with input as all_true
	c01.control_compliant with input as all_true
}

test_single_flip_one_violation if {
	inp := object.union(all_true, {"cis_controls": {"safeguards": {"1.3": false}}})
	count(c01.violation) == 1 with input as inp
	some msg in c01.violation with input as inp
	contains(msg, "1.3") with input as inp
}

test_compliance_report_populated if {
	rep := c01.compliance_report with input as {}
	rep.control == 1
	rep.safeguards_evaluated == count(c01.safeguards)
	rep.violation_count == count(c01.safeguards)
	rep.compliant == false
}
