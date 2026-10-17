package digital_sovereignty.ai_sovereignty_fixes_test

import rego.v1

ai := data.digital_sovereignty.ai_sovereignty

good := {
	"approved_jurisdictions": ["DE"],
	"ai_services": [],
	"ml_models": [],
	"ml_training": {
		"training_data_location_country": "DE",
		"training_infrastructure_country": "DE",
		"data_leaves_jurisdiction_for_training": false,
	},
	"ai_governance": {
		"policy_documented": true,
		"approved_ai_services_list": true,
		"data_handling_procedures": true,
		"shadow_ai_controls": true,
		"human_oversight_for_decisions": true,
	},
	"ai_output_controls": {"output_logging_enabled": true, "output_jurisdiction": "DE"},
	"ai_bias_fairness": {
		"bias_audit_policy_documented": true,
		"audit_findings_documented": true,
		"remediation_process_documented": true,
		"audit_frequency_days": 365000,
		"last_audit_date": "2020-01-01T00:00:00Z",
	},
	"ai_fairness_controls": {
		"fairness_metrics_defined": true,
		"fairness_thresholds_enforced": true,
		"disparate_impact_tested": true,
		"remediation_applied_when_breached": true,
		"fairness_monitoring_ongoing": true,
	},
}

with_svc(svc) := object.union(good, {"ai_services": [svc]})

with_model(m) := object.union(good, {"ml_models": [m]})

has_control(vs, c) if {
	some v in vs
	v.control == c
}

test_baseline_is_compliant if ai.compliant with input as good

test_saas_without_hq_country_violates_ai001 if {
	inp := with_svc({"service_id": "s1", "service_name": "n", "deployment_type": "saas", "data_classification_processed": "sensitive", "data_sent_for_inference": true, "inference_location_country": "DE"})
	not ai.no_regulated_data_to_foreign_ai with input as inp
	has_control(ai.violations, "AI-001") with input as inp
	not ai.compliant with input as inp
}

test_inference_without_location_violates_ai003 if {
	inp := with_svc({"service_id": "s1", "service_name": "n", "deployment_type": "self_hosted", "data_classification_processed": "sensitive", "provider_hq_country": "DE"})
	not ai.inference_in_approved_jurisdiction with input as inp
	has_control(ai.violations, "AI-003") with input as inp
}

test_inference_in_approved_country_ok if {
	inp := with_svc({"service_id": "s1", "service_name": "n", "deployment_type": "self_hosted", "data_classification_processed": "sensitive", "provider_hq_country": "DE", "inference_location_country": "DE"})
	ai.inference_in_approved_jurisdiction with input as inp
}

test_training_without_opt_out_violates_ai002 if {
	inp := with_svc({"service_id": "s1", "service_name": "n", "deployment_type": "saas", "data_classification_processed": "sensitive", "provider_hq_country": "DE", "inference_location_country": "DE", "data_used_for_training": true})
	has_control(ai.violations, "AI-002") with input as inp
}

test_model_without_weights_location_violates if {
	inp := with_model({"model_id": "m3", "model_name": "w", "origin": "open_source", "origin_country": "DE", "audited_for_backdoors": true})
	not ai.model_weights_in_jurisdiction with input as inp
	has_control(ai.violations, "AI-013") with input as inp
	not ai.compliant with input as inp
}

test_model_without_origin_country_must_be_audited if {
	inp := with_model({"model_id": "m6", "model_name": "u", "origin": "open_source", "audited_for_backdoors": false, "model_weights_location_country": "DE"})
	not ai.foreign_models_audited with input as inp
	has_control(ai.violations, "AI-006") with input as inp
}

test_model_without_origin_country_but_audited_ok if {
	inp := with_model({"model_id": "m6", "model_name": "u", "origin": "open_source", "audited_for_backdoors": true, "model_weights_location_country": "DE"})
	ai.foreign_models_audited with input as inp
}

test_training_flag_absent_is_not_compliant if {
	inp := object.union(good, {"ml_training": {"training_data_location_country": "FR", "training_infrastructure_country": "DE"}})
	not ai.training_data_in_jurisdiction with input as inp
	has_control(ai.violations, "AI-004") with input as inp
}

test_training_flag_false_but_foreign_location_violates if {
	inp := object.union(good, {"ml_training": {"training_data_location_country": "FR", "training_infrastructure_country": "DE", "data_leaves_jurisdiction_for_training": false}})
	not ai.training_data_in_jurisdiction with input as inp
}

test_missing_approved_jurisdictions_fails_closed if {
	inp := object.remove(with_model({"model_id": "m", "model_name": "w", "origin": "internal", "origin_country": "DE", "audited_for_backdoors": true, "model_weights_location_country": "DE"}), ["approved_jurisdictions"])
	not ai.model_weights_in_jurisdiction with input as inp
	not ai.compliant with input as inp
}

# Undefined-in-literal trap: report must exist while a control fails.
test_report_defined_with_failing_foreign_saas if {
	r := ai.report with input as with_svc({"service_id": "s1", "service_name": "n", "deployment_type": "saas", "provider_hq_country": "CN", "data_classification_processed": "sensitive", "data_sent_for_inference": true})
	r.compliant == false
	r.controls["AI-001_no_regulated_data_to_foreign_ai"] == false
	r.violation_count > 0
	r.service_summary.foreign_saas == 1
}

test_report_defined_with_failing_model_weights if {
	r := ai.report with input as with_model({"model_id": "m", "model_name": "w", "origin": "internal", "origin_country": "DE", "audited_for_backdoors": true, "model_weights_location_country": "FR"})
	r.compliant == false
	r.violation_count > 0
}

test_foreign_saas_summary_counts_missing_country if {
	r := ai.report with input as with_svc({"service_id": "s1", "service_name": "n", "deployment_type": "saas"})
	r.service_summary.foreign_saas == 1
}

test_governance_gaps_have_violations if {
	inp := object.union(good, {"ai_output_controls": {"output_logging_enabled": false, "output_jurisdiction": "US"}})
	has_control(ai.violations, "AI-015") with input as inp
	has_control(ai.violations, "AI-016") with input as inp
}
