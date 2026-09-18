package cis_controls_v8.c03_test

import rego.v1

import data.cis_controls_v8.c03

all_true := {"cis_controls": {"safeguards": {
	"3.1": true,
	"3.2": true,
	"3.3": true,
	"3.4": true,
	"3.5": true,
	"3.6": true,
	"3.7": true,
	"3.8": true,
	"3.9": true,
	"3.10": true,
	"3.11": true,
	"3.12": true,
	"3.13": true,
	"3.14": true,
}}}

test_empty_input_all_fire if {
	count(c03.violation) == count(c03.safeguards) with input as {}
	not c03.control_compliant with input as {}
}

test_all_attested_compliant if {
	count(c03.violation) == 0 with input as all_true
	c03.control_compliant with input as all_true
}

test_single_flip_one_violation if {
	inp := object.union(all_true, {"cis_controls": {"safeguards": {"3.11": false}}})
	count(c03.violation) == 1 with input as inp
	some msg in c03.violation with input as inp
	contains(msg, "3.11") with input as inp
}

test_compliance_report_populated if {
	rep := c03.compliance_report with input as {}
	rep.control == 3
	rep.safeguards_evaluated == count(c03.safeguards)
	rep.violation_count == count(c03.safeguards)
	rep.compliant == false
}
