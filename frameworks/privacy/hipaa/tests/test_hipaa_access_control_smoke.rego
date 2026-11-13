package hipaa.access_control_test

import rego.v1

import data.hipaa.test_fixtures as fx

# Generated smoke test for frameworks/privacy/hipaa/hipaa_access_control.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_hipaa_access_control_loads_on_empty_input if {
	m := data.hipaa.access_control with input as {}
	is_object(m)
}

test_hipaa_access_control_report_wellformed_on_empty_input if {
	report := data.hipaa.access_control.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_hipaa_access_control_fail_closed_on_empty_input if {
	report := data.hipaa.access_control.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_hipaa_access_control_violations_on_empty_input if {
	v := data.hipaa.access_control.violations with input as {}
	count(v) > 0
}

test_semrev_baseline_clean if {
	count(data.hipaa.access_control.violations) == 0 with input as fx.full_input
}

test_semrev_emergency_review_missing_fails if {
	inp := object.union(object.remove(fx.full_input, ["access_controls"]), {"access_controls": object.remove(fx.full_input.access_controls, ["emergency_accounts_reviewed_days"])})
	v := data.hipaa.access_control.violations with input as inp
	count(v) > 0
}

test_semrev_logoff_timeout_missing_fails if {
	inp := object.union(object.remove(fx.full_input, ["session"]), {"session": object.remove(fx.full_input.session, ["inactivity_timeout_minutes"])})
	v := data.hipaa.access_control.violations with input as inp
	count(v) > 0
}

test_semrev_screen_lock_missing_fails if {
	inp := object.union(object.remove(fx.full_input, ["session"]), {"session": object.remove(fx.full_input.session, ["screen_lock_enabled"])})
	v := data.hipaa.access_control.violations with input as inp
	count(v) > 0
}

test_semrev_key_rotation_missing_fails if {
	inp := object.union(object.remove(fx.full_input, ["encryption"]), {"encryption": object.remove(fx.full_input.encryption, ["key_rotation_days"])})
	v := data.hipaa.access_control.violations with input as inp
	count(v) > 0
}
