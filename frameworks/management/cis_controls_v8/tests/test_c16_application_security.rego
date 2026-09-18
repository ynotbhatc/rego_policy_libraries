package cis_controls_v8.c16_test

import rego.v1

import data.cis_controls_v8.c16

all_true := {"cis_controls": {"safeguards": {
	"16.1": true,
	"16.2": true,
	"16.3": true,
	"16.4": true,
	"16.5": true,
	"16.6": true,
	"16.7": true,
	"16.8": true,
	"16.9": true,
	"16.10": true,
	"16.11": true,
	"16.12": true,
	"16.13": true,
	"16.14": true,
}}}

test_empty_input_all_fire if {
	count(c16.violation) == count(c16.safeguards) with input as {}
	not c16.control_compliant with input as {}
}

test_all_attested_compliant if {
	count(c16.violation) == 0 with input as all_true
	c16.control_compliant with input as all_true
}

test_single_flip_one_violation if {
	inp := object.union(all_true, {"cis_controls": {"safeguards": {"16.13": false}}})
	count(c16.violation) == 1 with input as inp
	some msg in c16.violation with input as inp
	contains(msg, "16.13") with input as inp
}

test_compliance_report_populated if {
	rep := c16.compliance_report with input as {}
	rep.control == 16
	rep.safeguards_evaluated == count(c16.safeguards)
	rep.violation_count == count(c16.safeguards)
	rep.compliant == false
}
