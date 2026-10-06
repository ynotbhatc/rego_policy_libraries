# Tests for iso_42005.main.

package iso_42005.main_test

import rego.v1

import data.iso_42005.main

all_true := {"iso_42005": {
	"process": {
		"documented_repeatable_approach": true,
		"methodology_and_roles_documented": true,
		"integrated_with_management_processes": true,
		"lifecycle_triggers_defined": true,
		"responsibilities_allocated": true,
		"sensitive_use_thresholds_defined": true,
		"severity_likelihood_scales_defined": true,
		"approval_before_deployment_required": true,
		"monitoring_and_reassessment_defined": true,
		"integrated_with_aims": true,
	},
	"records": {
		"scope_stated": true,
		"unintended_uses_covered": true,
		"data_quality_documented": true,
		"model_versioned": true,
		"deployment_environment_described": true,
		"interested_parties_identified": true,
		"harms_and_benefits_assessed": true,
		"impacts_rated": true,
		"mitigations_with_owners": true,
		"approval_predates_deployment": true,
		"reviews_current": true,
		"related_assessments_cross_referenced": true,
	},
}}

test_fully_compliant if {
	main.compliant with input as all_true
	r := main.compliance_report with input as all_true
	r.violation_count == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 22
}

test_single_flip_fires if {
	inp := json.patch(all_true, [{"op": "replace", "path": "/iso_42005/records/unintended_uses_covered", "value": false}])
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "UNintended uses")
}

test_string_true_fails_closed if {
	inp := json.patch(all_true, [{"op": "replace", "path": "/iso_42005/process/approval_before_deployment_required", "value": "true"}])
	v := main.violations with input as inp
	count(v) == 1
}
