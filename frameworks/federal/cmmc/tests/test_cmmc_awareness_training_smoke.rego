package cmmc.awareness_training_test

import rego.v1

# Generated smoke test for frameworks/federal/cmmc/cmmc_awareness_training.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cmmc_awareness_training_loads_on_empty_input if {
	m := data.cmmc.awareness_training with input as {}
	is_object(m)
}

test_cmmc_awareness_training_report_wellformed_on_empty_input if {
	report := data.cmmc.awareness_training.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cmmc_awareness_training_fail_closed_on_empty_input if {
	report := data.cmmc.awareness_training.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# --- semantic review 2026-11-13: domain verdict must agree with practices ---

good_input_review := {"training": {"security_awareness_program": true, "all_users_trained": true, "training_frequency_days": 365, "role_based_training": true, "privileged_user_training": true, "training_records_maintained": true, "phishing_awareness_training": true, "social_engineering_training": true, "insider_threat_training": true}}

test_review_good_input_compliant if {
	r := data.cmmc.awareness_training.compliance_report with input as good_input_review
	r.compliant
	r.failing == 0
}

test_review_training_frequency_missing if {
	r := data.cmmc.awareness_training.compliance_report with input as {"training": {"security_awareness_program": true, "all_users_trained": true, "role_based_training": true, "privileged_user_training": true, "training_records_maintained": true, "phishing_awareness_training": true, "social_engineering_training": true, "insider_threat_training": true}}
	r.failing > 0
	not r.compliant
	count(r.violations) > 0
	some v in r.violations
	startswith(v, "3.2.")
}
