package cis_controls_v8.c12_test

import rego.v1

import data.cis_controls_v8.c12

all_true := {"cis_controls": {"safeguards": {
	"12.1": true,
	"12.2": true,
	"12.3": true,
	"12.4": true,
	"12.5": true,
	"12.6": true,
	"12.7": true,
	"12.8": true,
}}}

test_empty_input_all_fire if {
	count(c12.violation) == count(c12.safeguards) with input as {}
	not c12.control_compliant with input as {}
}

test_all_attested_compliant if {
	count(c12.violation) == 0 with input as all_true
	c12.control_compliant with input as all_true
}

test_single_flip_one_violation if {
	inp := object.union(all_true, {"cis_controls": {"safeguards": {"12.6": false}}})
	count(c12.violation) == 1 with input as inp
	some msg in c12.violation with input as inp
	contains(msg, "12.6") with input as inp
}

test_compliance_report_populated if {
	rep := c12.compliance_report with input as {}
	rep.control == 12
	rep.safeguards_evaluated == count(c12.safeguards)
	rep.violation_count == count(c12.safeguards)
	rep.compliant == false
}
