package cis_controls_v8.c08_test

import rego.v1

import data.cis_controls_v8.c08

all_true := {"cis_controls": {"safeguards": {
	"8.1": true,
	"8.2": true,
	"8.3": true,
	"8.4": true,
	"8.5": true,
	"8.6": true,
	"8.7": true,
	"8.8": true,
	"8.9": true,
	"8.10": true,
	"8.11": true,
	"8.12": true,
}}}

test_empty_input_all_fire if {
	count(c08.violation) == count(c08.safeguards) with input as {}
	not c08.control_compliant with input as {}
}

test_all_attested_compliant if {
	count(c08.violation) == 0 with input as all_true
	c08.control_compliant with input as all_true
}

test_single_flip_one_violation if {
	inp := object.union(all_true, {"cis_controls": {"safeguards": {"8.10": false}}})
	count(c08.violation) == 1 with input as inp
	some msg in c08.violation with input as inp
	contains(msg, "8.10") with input as inp
}

test_compliance_report_populated if {
	rep := c08.compliance_report with input as {}
	rep.control == 8
	rep.safeguards_evaluated == count(c08.safeguards)
	rep.violation_count == count(c08.safeguards)
	rep.compliant == false
}
