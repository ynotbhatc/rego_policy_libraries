package nerc_cip.cip_002_test

import rego.v1

import data.nerc_cip.cip_002 as c

# Validation 2026-10-17: Attachment 1 criteria now gate compliance.

now_rfc := time.format([time.now_ns(), "UTC", "2006-01-02T15:04:05Z07:00"])

high_system := {"system_id": "S1", "system_name": "EMS", "functional_obligations": ["x"], "cyber_assets": ["a"], "impact_categorization": "high"}

attachment1 := {"high_impact_criteria": {
	"criterion_2_1_control_centers": {"evaluated": true},
	"criterion_2_2_transmission_facilities": {"evaluated": true},
	"criterion_2_3_generation": {"evaluated": true},
	"criterion_2_4_systems": {"evaluated": true},
	"criterion_2_5_fca": {"evaluated": true},
	"criterion_2_6_eacms": {"evaluated": true},
	"rationale_documented": true,
}}

base := {
	"bes_cyber_systems": [high_system],
	"categorization_documentation": {
		"criteria_defined": true,
		"methodology_documented": true,
		"rationale_provided": true,
		"attachment1_used": true,
		"last_review_date": now_rfc,
		"cip_senior_manager_approved": true,
		"approval_date": now_rfc,
	},
	"attachment1": attachment1,
}

test_complete_evidence_is_compliant if {
	c.compliant with input as base
}

test_high_impact_without_attachment1_not_compliant if {
	i := json.remove(base, ["attachment1"])
	not c.compliant with input as i
	count([v | some v in c.violations with input as i; contains(v.description, "High impact")]) == 1
}

test_unassessed_environment_change_not_compliant if {
	i := json.patch(base, [{"op": "add", "path": "/bes_environment_changes", "value": [{"categorization_impact_assessed": true, "categorization_updated_if_needed": false}]}])
	not c.compliant with input as i
}

test_invalid_eacms_not_compliant if {
	i := json.patch(base, [{"op": "add", "path": "/electronic_access_control_systems", "value": [{"associated_bes_system_id": "S1", "impact_categorization": "bogus", "classification_rationale": "r"}]}])
	not c.compliant with input as i
}

test_report_fully_populated_on_empty_input if {
	r := c.report with input as {}
	r.compliant == false
	r.requirements.R1_high_impact_criteria == false
}
