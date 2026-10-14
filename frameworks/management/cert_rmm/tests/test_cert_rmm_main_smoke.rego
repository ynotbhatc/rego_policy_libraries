package cert_rmm.main_test

import rego.v1

# Generated smoke test for frameworks/management/cert_rmm/cert_rmm_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cert_rmm_main_loads_on_empty_input if {
	m := data.cert_rmm.main with input as {}
	is_object(m)
}

test_cert_rmm_main_report_wellformed_on_empty_input if {
	report := data.cert_rmm.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cert_rmm_main_fail_closed_on_empty_input if {
	report := data.cert_rmm.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_cert_rmm_main_violations_on_empty_input if {
	v := data.cert_rmm.main.violations with input as {}
	count(v) > 0
}
