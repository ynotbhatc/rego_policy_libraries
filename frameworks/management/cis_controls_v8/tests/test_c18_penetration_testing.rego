package cis_controls_v8.c18_test

import rego.v1

import data.cis_controls_v8.c18

all_true := {"cis_controls": {"safeguards": {
	"18.1": true,
	"18.2": true,
	"18.3": true,
	"18.4": true,
	"18.5": true,
}}}

test_empty_input_all_fire if {
	count(c18.violation) == count(c18.safeguards) with input as {}
	not c18.control_compliant with input as {}
}

test_all_attested_compliant if {
	count(c18.violation) == 0 with input as all_true
	c18.control_compliant with input as all_true
}

test_single_flip_one_violation if {
	inp := object.union(all_true, {"cis_controls": {"safeguards": {"18.3": false}}})
	count(c18.violation) == 1 with input as inp
	some msg in c18.violation with input as inp
	contains(msg, "18.3") with input as inp
}

test_compliance_report_populated if {
	rep := c18.compliance_report with input as {}
	rep.control == 18
	rep.safeguards_evaluated == count(c18.safeguards)
	rep.violation_count == count(c18.safeguards)
	rep.compliant == false
}
