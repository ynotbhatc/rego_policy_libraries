package cjis.auditing_accountability_test

import rego.v1

import data.cjis.auditing_accountability

# Build an all-attested input from the requirement ids.
all_attested := {"cjis": {"auditing_accountability": {"requirements": reqs}}} if {
	reqs := {id: true | some id, _ in auditing_accountability.requirements}
}

test_empty_input_all_violations_fire if {
	v := auditing_accountability.violation with input as {}
	count(v) == count(auditing_accountability.requirements)
}

test_empty_input_not_compliant if {
	not auditing_accountability.area_compliant with input as {}
}

test_all_attested_no_violations if {
	v := auditing_accountability.violation with input as all_attested
	count(v) == 0
}

test_all_attested_compliant if {
	auditing_accountability.area_compliant with input as all_attested
}

test_single_flip_one_violation if {
	flipped := object.union(all_attested, {"cjis": {"auditing_accountability": {"requirements": object.union(
		{id: true | some id, _ in auditing_accountability.requirements},
		{"AA-3": false},
	)}}})
	v := auditing_accountability.violation with input as flipped
	count(v) == 1
	some msg in v
	contains(msg, "AA-3")
}

test_report_populated_on_empty_input if {
	r := auditing_accountability.compliance_report with input as {}
	r.policy_area == 4
	r.area_name == "Auditing and Accountability"
	r.requirements_evaluated == count(auditing_accountability.requirements)
	r.violation_count == count(auditing_accountability.requirements)
	r.compliant == false
}
