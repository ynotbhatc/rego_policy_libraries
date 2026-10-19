package nerc_cip.cip_008_test

import rego.v1

import data.nerc_cip.cip_008 as c

test_incident_classification_process_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-008 R1.5: incident classification process requirement not met"]) == 1
}

test_plan_communicated_to_personnel_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-008 R2.3: plan communicated to personnel requirement not met"]) == 1
}

test_incident_response_test_documented_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-008 R3.1: incident response test documented requirement not met"]) == 1
}

test_lessons_learned_incorporated_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-008 R3.2: lessons learned incorporated requirement not met"]) == 1
}

test_reportable_incident_identification_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-008 R5: reportable incident identification requirement not met"]) == 1
}
