package cjis.access_control_test

import rego.v1

import data.cjis.access_control

all_attested := {"cjis": {"access_control": {"requirements": reqs}}} if {
	reqs := {id: true | some id, _ in access_control.requirements}
}

test_empty_input_all_violations_fire if {
	v := access_control.violation with input as {}
	count(v) == count(access_control.requirements)
}

test_empty_input_not_compliant if {
	not access_control.area_compliant with input as {}
}

test_all_attested_no_violations if {
	v := access_control.violation with input as all_attested
	count(v) == 0
}

test_all_attested_compliant if {
	access_control.area_compliant with input as all_attested
}

test_single_flip_one_violation if {
	flipped := {"cjis": {"access_control": {"requirements": object.union(
		{id: true | some id, _ in access_control.requirements},
		{"AC-4": false},
	)}}}
	v := access_control.violation with input as flipped
	count(v) == 1
	some msg in v
	contains(msg, "AC-4")
}

test_report_populated_on_empty_input if {
	r := access_control.compliance_report with input as {}
	r.policy_area == 5
	r.area_name == "Access Control"
	r.requirements_evaluated == count(access_control.requirements)
	r.violation_count == count(access_control.requirements)
	r.compliant == false
}
