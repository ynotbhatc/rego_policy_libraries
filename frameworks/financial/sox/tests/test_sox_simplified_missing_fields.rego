package sox.simplified_test

import rego.v1

full := {"sox": {
	"section_302": {
		"ceo_certification": {"provided": true},
		"cfo_certification": {"provided": true},
		"disclosure_controls": {"effective": true},
		"material_weaknesses": {"none_identified": true},
		"quarterly_review": {"completed": true},
		"annual_assessment": {"completed": true},
	},
	"section_404": {
		"management_assessment": {"completed": true},
		"internal_controls": {"designed_effectively": true, "operating_effectively": true},
		"external_auditor_attestation": {"unqualified": true},
		"remediation_plan": {"implemented": true},
		"continuous_monitoring": {"active": true},
	},
	"section_409": {
		"material_events": {"disclosed_timely": true},
		"disclosure_process": {"automated": true},
		"disclosure_controls": {"reviewed_quarterly": true},
		"event_detection": {"real_time": true},
		"filing_deadlines": {"met": true},
	},
	"itgc": {
		"access_controls": {"implemented": true},
		"change_management": {"controlled": true},
		"computer_operations": {"monitored": true},
		"system_development": {"secure": true},
		"data_center_operations": {"controlled": true},
		"backup_recovery": {"tested": true},
	},
}}

no_ceo := json.remove(full, ["sox/section_302/ceo_certification"])

test_full_input_compliant if data.sox.simplified.sox_compliant with input as full

test_missing_ceo_still_reports_finding if {
	f := data.sox.simplified.section_302_findings with input as no_ceo
	names := {x.control_name | some x in f}
	"CEO Certification" in names
}

test_missing_ceo_keeps_score_and_assessment_defined if {
	s := data.sox.simplified.sox_compliance_score with input as no_ceo
	s > 0
	s < 1
	a := data.sox.simplified.overall_sox_assessment with input as no_ceo
	is_object(a)
	not data.sox.simplified.sox_compliant with input as no_ceo
}

test_empty_input_score_defined if {
	data.sox.simplified.sox_compliance_score == 0 with input as {}
}

test_data_center_operations_gates_verdict if {
	inp := json.remove(full, ["sox/itgc/data_center_operations"])
	not data.sox.simplified.sox_compliant with input as inp
	not data.sox.simplified.itgc_compliant with input as inp
}
