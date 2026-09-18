package cis_controls_v8.c09_test

import rego.v1

import data.cis_controls_v8.c09

all_true := {"cis_controls": {"safeguards": {
	"9.1": true,
	"9.2": true,
	"9.3": true,
	"9.4": true,
	"9.5": true,
	"9.6": true,
	"9.7": true,
}}}

test_empty_input_all_fire if {
	count(c09.violation) == count(c09.safeguards) with input as {}
	not c09.control_compliant with input as {}
}

test_all_attested_compliant if {
	count(c09.violation) == 0 with input as all_true
	c09.control_compliant with input as all_true
}

test_single_flip_one_violation if {
	inp := object.union(all_true, {"cis_controls": {"safeguards": {"9.4": false}}})
	count(c09.violation) == 1 with input as inp
	some msg in c09.violation with input as inp
	contains(msg, "9.4") with input as inp
}

test_compliance_report_populated if {
	rep := c09.compliance_report with input as {}
	rep.control == 9
	rep.safeguards_evaluated == count(c09.safeguards)
	rep.violation_count == count(c09.safeguards)
	rep.compliant == false
}
