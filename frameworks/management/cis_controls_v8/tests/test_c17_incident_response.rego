package cis_controls_v8.c17_test

import rego.v1

import data.cis_controls_v8.c17

all_true := {"cis_controls": {"safeguards": {
	"17.1": true,
	"17.2": true,
	"17.3": true,
	"17.4": true,
	"17.5": true,
	"17.6": true,
	"17.7": true,
	"17.8": true,
	"17.9": true,
}}}

test_empty_input_all_fire if {
	count(c17.violation) == count(c17.safeguards) with input as {}
	not c17.control_compliant with input as {}
}

test_all_attested_compliant if {
	count(c17.violation) == 0 with input as all_true
	c17.control_compliant with input as all_true
}

test_single_flip_one_violation if {
	inp := object.union(all_true, {"cis_controls": {"safeguards": {"17.4": false}}})
	count(c17.violation) == 1 with input as inp
	some msg in c17.violation with input as inp
	contains(msg, "17.4") with input as inp
}

test_compliance_report_populated if {
	rep := c17.compliance_report with input as {}
	rep.control == 17
	rep.safeguards_evaluated == count(c17.safeguards)
	rep.violation_count == count(c17.safeguards)
	rep.compliant == false
}
