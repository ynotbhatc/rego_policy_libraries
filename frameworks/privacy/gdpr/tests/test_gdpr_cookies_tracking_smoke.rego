package gdpr.cookies_tracking_test

import rego.v1

# Generated smoke test for frameworks/privacy/gdpr/gdpr_cookies_tracking.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_gdpr_cookies_tracking_loads_on_empty_input if {
	m := data.gdpr.cookies_tracking with input as {}
	is_object(m)
}

test_gdpr_cookies_tracking_report_wellformed_on_empty_input if {
	report := data.gdpr.cookies_tracking.report with input as {}
	is_object(report)
	count(report) > 0
}

test_gdpr_cookies_tracking_fail_closed_on_empty_input if {
	report := data.gdpr.cookies_tracking.report with input as {}
	not object.get(report, "compliant", false) == true
}
