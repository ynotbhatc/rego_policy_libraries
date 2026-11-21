package digital_sovereignty.numeric_guards_test

import rego.v1

# A regulated-data AI service whose retention period is not a number is evidence missing, not zero retention.
test_non_number_retention_days_is_evidence_missing if {
	every v in ["1", null, "x"] {
		vs := data.digital_sovereignty.ai_sovereignty.violations with input as {"ai_services": [{
			"service_name": "svc-a",
			"data_classification_processed": "restricted",
			"data_retention_by_provider_days": v,
		}]}
		some x in vs
		x.description == "AI-011: evidence missing - data_retention_by_provider_days is not a number for svc-a"
		not data.digital_sovereignty.ai_sovereignty.no_long_term_ai_data_retention with input as {"ai_services": [{
			"service_name": "svc-a",
			"data_classification_processed": "restricted",
			"data_retention_by_provider_days": v,
		}]}
	}
}

test_numeric_retention_days_unchanged if {
	data.digital_sovereignty.ai_sovereignty.no_long_term_ai_data_retention with input as {"ai_services": [{
		"service_name": "svc-a",
		"data_classification_processed": "restricted",
		"data_retention_by_provider_days": 0,
	}]}
	not data.digital_sovereignty.ai_sovereignty.no_long_term_ai_data_retention with input as {"ai_services": [{
		"service_name": "svc-a",
		"data_classification_processed": "restricted",
		"data_retention_by_provider_days": 30,
	}]}
}

test_non_number_rotation_days_not_met if {
	every v in ["1", null, "x"] {
		not data.digital_sovereignty.cryptographic_sovereignty.key_rotation_policy with input as {"key_management_policies": {"rotation_policy_documented": true, "rotation_frequency_days": v}}
	}
	data.digital_sovereignty.cryptographic_sovereignty.key_rotation_policy with input as {"key_management_policies": {"rotation_policy_documented": true, "rotation_frequency_days": 365}}
}
