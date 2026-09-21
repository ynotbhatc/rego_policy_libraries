package cjis.personnel_security_test

import rego.v1

import data.cjis.personnel_security

# Empty input: every requirement fires and the area is not compliant.
test_empty_input_all_violations if {
	count(personnel_security.violation) == count(personnel_security.requirements) with input as {}
	not personnel_security.area_compliant with input as {}
}

# All requirements attested: no violations, area compliant.
all_attested := {"cjis": {"personnel_security": {"requirements": att}}} if {
	att := {id: true | some id, _ in personnel_security.requirements}
}

test_all_attested_compliant if {
	count(personnel_security.violation) == 0 with input as all_attested
	personnel_security.area_compliant with input as all_attested
}

# Single flip: exactly one requirement unmet yields exactly one violation for that id.
test_single_flip_one_violation if {
	att := {id: true | some id, _ in personnel_security.requirements}
	flipped := object.union(att, {"PS-5": false})
	in_data := {"cjis": {"personnel_security": {"requirements": flipped}}}
	count(personnel_security.violation) == 1 with input as in_data
	some msg in personnel_security.violation with input as in_data
	contains(msg, "PS-5") with input as in_data
}

# Report is populated on empty input (fail-closed, not collapsed to {}).
test_report_populated_on_empty if {
	rep := personnel_security.compliance_report with input as {}
	rep.policy_area == 12
	rep.area_name == "Personnel Security"
	rep.requirements_evaluated == count(personnel_security.requirements)
	rep.violation_count == count(personnel_security.requirements)
	rep.compliant == false
}
