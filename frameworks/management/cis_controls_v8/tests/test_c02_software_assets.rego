package cis_controls_v8.c02_test

import rego.v1

import data.cis_controls_v8.c02

all_true := {"cis_controls": {"safeguards": {
	"2.1": true,
	"2.2": true,
	"2.3": true,
	"2.4": true,
	"2.5": true,
	"2.6": true,
	"2.7": true,
}}}

test_empty_input_all_fire if {
	count(c02.violation) == count(c02.safeguards) with input as {}
	not c02.control_compliant with input as {}
}

test_all_attested_compliant if {
	count(c02.violation) == 0 with input as all_true
	c02.control_compliant with input as all_true
}

test_single_flip_one_violation if {
	inp := object.union(all_true, {"cis_controls": {"safeguards": {"2.5": false}}})
	count(c02.violation) == 1 with input as inp
	some msg in c02.violation with input as inp
	contains(msg, "2.5") with input as inp
}

test_compliance_report_populated if {
	rep := c02.compliance_report with input as {}
	rep.control == 2
	rep.safeguards_evaluated == count(c02.safeguards)
	rep.violation_count == count(c02.safeguards)
	rep.compliant == false
}
