package fisma.ssp_fixes_test

import rego.v1

ssp := data.fisma.ssp

ctl := {
	"control_id": "AC-2",
	"control_name": "Account Management",
	"control_description": "d",
	"implementation_status": "implemented",
	"implementation_description": "i",
	"responsible_role": "ISSO",
	"implementation_guidance": "g",
}

with_controls(cs) := {"ssp": {"controls": {"implemented_controls": cs}}}

test_empty_controls_descriptions_not_complete if not ssp.control_descriptions_complete with input as with_controls([])

test_empty_controls_details_not_provided if not ssp.control_implementation_details_provided with input as with_controls([])

test_missing_controls_not_complete if not ssp.control_descriptions_complete with input as {}

test_valid_control_descriptions_complete if ssp.control_descriptions_complete with input as with_controls([ctl])

test_valid_control_details_provided if ssp.control_implementation_details_provided with input as with_controls([ctl])

test_incomplete_control_description_fails if not ssp.control_descriptions_complete with input as with_controls([object.union(ctl, {"control_name": ""})])

test_assessment_defined_when_sections_fail if {
	a := ssp.ssp_assessment with input as {}
	a.ssp_compliant == false
	count(a.sections_assessment) == 7
}

test_quality_score_survives_failing_sections if {
	s := ssp.ssp_quality_score with input as {}
		with data.fisma.ssp.ssp_document_structure_valid as true
		with data.fisma.ssp.ssp_maintenance_current as true
	s == 200 / 7
}

test_quality_score_zero_on_empty if ssp.ssp_quality_score == 0 with input as {}
