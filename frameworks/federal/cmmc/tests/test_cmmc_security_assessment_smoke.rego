package cmmc.security_assessment_test

import rego.v1

# Generated smoke test for frameworks/federal/cmmc/cmmc_security_assessment.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cmmc_security_assessment_loads_on_empty_input if {
	m := data.cmmc.security_assessment with input as {}
	is_object(m)
}

test_cmmc_security_assessment_report_wellformed_on_empty_input if {
	report := data.cmmc.security_assessment.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cmmc_security_assessment_fail_closed_on_empty_input if {
	report := data.cmmc.security_assessment.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# --- semantic review 2026-11-13: domain verdict must agree with practices ---

good_input_review := {"assessment": {"security_controls_assessed": true, "assessment_frequency_days": 365, "assessment_results_documented": true, "plan_of_action_exists": true, "poam_tracks_deficiencies": true, "poam_reviewed_regularly": true, "continuous_monitoring_program": true, "security_metrics_collected": true, "control_effectiveness_reviewed": true, "system_security_plan_exists": true, "ssp_documents_boundaries": true, "ssp_documents_cui_environment": true, "ssp_updated_annually": true}}

test_review_good_input_compliant if {
	r := data.cmmc.security_assessment.compliance_report with input as good_input_review
	r.compliant
	r.failing == 0
}

test_review_assessment_frequency_missing if {
	r := data.cmmc.security_assessment.compliance_report with input as {"assessment": {"security_controls_assessed": true, "assessment_results_documented": true, "plan_of_action_exists": true, "poam_tracks_deficiencies": true, "poam_reviewed_regularly": true, "continuous_monitoring_program": true, "security_metrics_collected": true, "control_effectiveness_reviewed": true, "system_security_plan_exists": true, "ssp_documents_boundaries": true, "ssp_documents_cui_environment": true, "ssp_updated_annually": true}}
	r.failing > 0
	not r.compliant
	count(r.violations) > 0
	some v in r.violations
	startswith(v, "3.12.")
}
