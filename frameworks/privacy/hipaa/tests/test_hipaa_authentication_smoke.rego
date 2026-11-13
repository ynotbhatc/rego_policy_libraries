package hipaa.authentication_test

import rego.v1

import data.hipaa.test_fixtures as fx

# Generated smoke test for frameworks/privacy/hipaa/hipaa_authentication.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_hipaa_authentication_loads_on_empty_input if {
	m := data.hipaa.authentication with input as {}
	is_object(m)
}

test_hipaa_authentication_report_wellformed_on_empty_input if {
	report := data.hipaa.authentication.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_hipaa_authentication_fail_closed_on_empty_input if {
	report := data.hipaa.authentication.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_hipaa_authentication_violations_on_empty_input if {
	v := data.hipaa.authentication.violations with input as {}
	count(v) > 0
}

test_semrev_baseline_clean if {
	count(data.hipaa.authentication.violations) == 0 with input as fx.full_input
}

test_semrev_password_length_missing_fails if {
	inp := object.union(object.remove(fx.full_input, ["password_policy"]), {"password_policy": object.remove(fx.full_input.password_policy, ["minimum_length"])})
	v := data.hipaa.authentication.violations with input as inp
	count(v) > 0
}

test_semrev_password_max_age_missing_fails if {
	inp := object.union(object.remove(fx.full_input, ["password_policy"]), {"password_policy": object.remove(fx.full_input.password_policy, ["max_age_days"])})
	v := data.hipaa.authentication.violations with input as inp
	count(v) > 0
}

test_semrev_password_history_missing_fails if {
	inp := object.union(object.remove(fx.full_input, ["password_policy"]), {"password_policy": object.remove(fx.full_input.password_policy, ["history_count"])})
	v := data.hipaa.authentication.violations with input as inp
	count(v) > 0
}

test_semrev_password_lockout_threshold_missing_fails if {
	inp := object.union(object.remove(fx.full_input, ["password_policy"]), {"password_policy": object.remove(fx.full_input.password_policy, ["lockout_threshold"])})
	v := data.hipaa.authentication.violations with input as inp
	count(v) > 0
}
