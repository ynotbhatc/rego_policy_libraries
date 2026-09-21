package cjis.identification_authentication_test

import rego.v1

import data.cjis.identification_authentication

all_attested := {"cjis": {"identification_authentication": {"requirements": reqs}}} if {
	reqs := {id: true | some id, _ in identification_authentication.requirements}
}

test_empty_input_all_violations_fire if {
	v := identification_authentication.violation with input as {}
	count(v) == count(identification_authentication.requirements)
}

test_empty_input_not_compliant if {
	not identification_authentication.area_compliant with input as {}
}

test_all_attested_no_violations if {
	v := identification_authentication.violation with input as all_attested
	count(v) == 0
}

test_all_attested_compliant if {
	identification_authentication.area_compliant with input as all_attested
}

test_single_flip_one_violation if {
	flipped := {"cjis": {"identification_authentication": {"requirements": object.union(
		{id: true | some id, _ in identification_authentication.requirements},
		{"IA-2": false},
	)}}}
	v := identification_authentication.violation with input as flipped
	count(v) == 1
	some msg in v
	contains(msg, "IA-2")
}

test_report_populated_on_empty_input if {
	r := identification_authentication.compliance_report with input as {}
	r.policy_area == 6
	r.area_name == "Identification and Authentication"
	r.requirements_evaluated == count(identification_authentication.requirements)
	r.violation_count == count(identification_authentication.requirements)
	r.compliant == false
}
