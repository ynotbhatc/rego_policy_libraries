package sox.main_test

import rego.v1

s302 := {
	"ceo_certification": {"provided": true},
	"cfo_certification": {"provided": true},
	"disclosure_controls": {"effective": true},
	"material_weaknesses": {"none_identified": true},
	"quarterly_review": {"completed": true},
	"annual_assessment": {"completed": true},
}

s404 := {
	"management_assessment": {"completed": true},
	"internal_controls": {"designed_effectively": true, "operating_effectively": true},
	"external_auditor_attestation": {"unqualified": true},
	"remediation_plan": {"implemented": true},
	"continuous_monitoring": {"active": true},
}

s409 := {
	"material_events": {"disclosed_timely": true},
	"disclosure_process": {"automated": true},
	"disclosure_controls": {"reviewed_quarterly": true},
	"event_detection": {"real_time": true},
	"filing_deadlines": {"met": true},
}

mgmt := {
	"assessment_framework": {"documented": true},
	"testing_procedures": {"comprehensive": true},
	"deficiency_remediation": {"timely": true},
	"continuous_monitoring": {"implemented": true},
	"risk_assessment": {"annual": true},
	"control_documentation": {"current": true},
}

itgc_ok := {
	"access_controls": {"implemented": true},
	"change_management": {"controlled": true},
	"computer_operations": {"monitored": true},
	"system_development": {"secure": true},
	"data_center_operations": {"controlled": true},
	"backup_recovery": {"tested": true},
}

app_ok := {
	"input_validation": {"comprehensive": true},
	"processing_controls": {"accurate": true},
	"output_controls": {"complete": true},
	"data_integrity": {"maintained": true},
	"error_handling": {"robust": true},
	"transaction_logging": {"complete": true},
}

itgc_bad := object.union(itgc_ok, {"access_controls": {"implemented": false}})

test_all_areas_pass_is_fully_compliant if {
	data.sox.main.sox_compliant with data.sox.section_302 as s302 with data.sox.section_404 as s404 with data.sox.section_409 as s409 with data.sox.management as mgmt with data.sox.itgc as itgc_ok with data.sox.application_controls as app_ok
	data.sox.main.sox_compliance_level == "FULLY_COMPLIANT" with data.sox.section_302 as s302 with data.sox.section_404 as s404 with data.sox.section_409 as s409 with data.sox.management as mgmt with data.sox.itgc as itgc_ok with data.sox.application_controls as app_ok
}

test_failed_itgc_area_blocks_verdict_and_fully_compliant if {
	not data.sox.main.sox_compliant with data.sox.section_302 as s302 with data.sox.section_404 as s404 with data.sox.section_409 as s409 with data.sox.management as mgmt with data.sox.itgc as itgc_bad with data.sox.application_controls as app_ok
	lvl := data.sox.main.sox_compliance_level with data.sox.section_302 as s302 with data.sox.section_404 as s404 with data.sox.section_409 as s409 with data.sox.management as mgmt with data.sox.itgc as itgc_bad with data.sox.application_controls as app_ok
	lvl != "FULLY_COMPLIANT"
}

test_failed_app_control_blocks_verdict if {
	app_bad := object.union(app_ok, {"error_handling": {"robust": false}})
	not data.sox.main.sox_compliant with data.sox.section_302 as s302 with data.sox.section_404 as s404 with data.sox.section_409 as s409 with data.sox.management as mgmt with data.sox.itgc as itgc_ok with data.sox.application_controls as app_bad
}

test_missing_field_still_reports_that_control_finding if {
	s := object.remove(s302, ["ceo_certification"])
	f := data.sox.main.section_302_findings with data.sox.section_302 as s
	names := {x.control_name | some x in f}
	"CEO Certification" in names
}

test_missing_field_does_not_zero_whole_section_score if {
	s := object.remove(s302, ["ceo_certification"])
	score := data.sox.main.section_302_score with data.sox.section_302 as s
	score > 0
}
