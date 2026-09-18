package cis_controls_v8.c13_test

import rego.v1

import data.cis_controls_v8.c13

# All safeguard IDs, mapped to true (fully attested input).
all_attested := {"cis_controls": {"safeguards": {id: true | some id, _ in c13.safeguards}}}

test_empty_input_all_fire if {
	count(c13.violation) == count(c13.safeguards) with input as {}
	not c13.control_compliant with input as {}
}

test_all_attested_no_violations if {
	count(c13.violation) == 0 with input as all_attested
	c13.control_compliant with input as all_attested
}

test_single_flip_one_violation if {
	flipped := object.union(all_attested, {"cis_controls": {"safeguards": object.union(all_attested.cis_controls.safeguards, {"13.4": false})}})
	count(c13.violation) == 1 with input as flipped
	not c13.control_compliant with input as flipped
	some msg in c13.violation with input as flipped
	contains(msg, "13.4")
}

test_report_populated_on_empty_input if {
	report := c13.compliance_report with input as {}
	report.control == 13
	report.name == "Network Monitoring and Defense"
	report.safeguards_evaluated == count(c13.safeguards)
	report.violation_count == count(c13.safeguards)
	report.compliant == false
}
