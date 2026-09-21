package cjis.formal_audits_test

import rego.v1

import data.cjis.formal_audits

# Empty input → every requirement fires and the area is not compliant.
test_empty_input_all_fire if {
	count(formal_audits.violation) == count(formal_audits.requirements) with input as {}
	not formal_audits.area_compliant with input as {}
}

# All requirements attested → no violations and the area is compliant.
test_all_attested_compliant if {
	attested := {id: true | some id, _ in formal_audits.requirements}
	in_val := {"cjis": {"formal_audits": {"requirements": attested}}}
	count(formal_audits.violation) == 0 with input as in_val
	formal_audits.area_compliant with input as in_val
}

# Flip a single requirement false → exactly one violation, carrying that id.
test_single_flip_one_violation if {
	attested := {id: true | some id, _ in formal_audits.requirements}
	flipped := object.union(attested, {"FA-4": false})
	in_val := {"cjis": {"formal_audits": {"requirements": flipped}}}
	count(formal_audits.violation) == 1 with input as in_val
	some msg in formal_audits.violation with input as in_val
	contains(msg, "FA-4") with input as in_val
}

# Report is populated on empty input.
test_report_populated_on_empty if {
	rep := formal_audits.compliance_report with input as {}
	rep.policy_area == 11
	rep.area_name == "Formal Audits"
	rep.requirements_evaluated == count(formal_audits.requirements)
	rep.violation_count == count(formal_audits.requirements)
	rep.compliant == false
}
