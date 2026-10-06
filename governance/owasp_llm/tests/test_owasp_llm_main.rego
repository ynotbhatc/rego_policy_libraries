# Tests for owasp_llm.main — 2026 edition.

package owasp_llm.main_test

import rego.v1

import data.owasp_llm.main

all_true := {"owasp_llm": {
	"llm01": {"privilege_separation_enforced": true, "untrusted_input_filtered": true, "high_impact_actions_gated": true},
	"llm02": {"data_sanitized_before_use": true, "retrieval_access_controlled": true, "outputs_scanned_for_sensitive_data": true},
	"llm03": {"tools_minimized": true, "downstream_permissions_least_privilege": true, "consequential_actions_require_human": true},
	"llm04": {"model_artifacts_verified": true, "aibom_maintained": true, "vetted_sources_only": true},
	"llm05": {"training_data_provenance_tracked": true, "behavior_shaping_stores_write_restricted": true, "pre_release_behavioral_testing": true},
	"llm06": {"rate_limits_enforced": true, "workflow_resource_metering": true, "spend_circuit_breakers": true},
	"llm07": {"high_stakes_outputs_grounded": true, "independent_verification_path": true, "limitations_communicated": true},
	"llm08": {"no_secrets_in_model_visible_context": true, "guardrails_outside_model": true, "sensitive_config_separated": true},
	"llm09": {"retrieval_authorization_enforced": true, "vector_stores_tenant_isolated": true, "embedding_leakage_monitored": true},
	"llm10": {"output_treated_as_untrusted": true, "deterministic_output_validation": true, "generated_code_sandboxed": true},
}}

test_fully_compliant if {
	main.compliant with input as all_true
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 30
}

test_single_flip_fires if {
	inp := json.patch(all_true, [{"op": "replace", "path": "/owasp_llm/llm03/consequential_actions_require_human", "value": false}])
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "LLM03:2026")
	contains(msg, "human-in-the-loop")
}

test_string_true_fails_closed if {
	inp := json.patch(all_true, [{"op": "replace", "path": "/owasp_llm/llm08/guardrails_outside_model", "value": "yes"}])
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "LLM08:2026")
}

test_atlas_crosswalk_complete if {
	count(main.atlas_crosswalk) == 10
	every _, m in main.atlas_crosswalk {
		count(m.mitigations) > 0
		every mit in m.mitigations {
			startswith(mit, "AML.M")
		}
	}
}

test_report_carries_crosswalk if {
	r := main.compliance_report with input as {}
	count(r.atlas_crosswalk) == 10
}
