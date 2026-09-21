package cjis.systems_communications_protection_test

import rego.v1

import data.cjis.systems_communications_protection

# Empty input → every requirement fires and the area is not compliant.
test_empty_input_all_fire if {
	count(systems_communications_protection.violation) == count(systems_communications_protection.requirements) with input as {}
	not systems_communications_protection.area_compliant with input as {}
}

# All requirements attested → no violations and the area is compliant.
test_all_attested_compliant if {
	attested := {id: true | some id, _ in systems_communications_protection.requirements}
	in_val := {"cjis": {"systems_communications_protection": {"requirements": attested}}}
	count(systems_communications_protection.violation) == 0 with input as in_val
	systems_communications_protection.area_compliant with input as in_val
}

# Flip a single requirement false → exactly one violation, carrying that id.
test_single_flip_one_violation if {
	attested := {id: true | some id, _ in systems_communications_protection.requirements}
	flipped := object.union(attested, {"SC-3": false})
	in_val := {"cjis": {"systems_communications_protection": {"requirements": flipped}}}
	count(systems_communications_protection.violation) == 1 with input as in_val
	some msg in systems_communications_protection.violation with input as in_val
	contains(msg, "SC-3") with input as in_val
}

# Report is populated on empty input.
test_report_populated_on_empty if {
	rep := systems_communications_protection.compliance_report with input as {}
	rep.policy_area == 10
	rep.area_name == "Systems and Communications Protection and Information Integrity"
	rep.requirements_evaluated == count(systems_communications_protection.requirements)
	rep.violation_count == count(systems_communications_protection.requirements)
	rep.compliant == false
}
