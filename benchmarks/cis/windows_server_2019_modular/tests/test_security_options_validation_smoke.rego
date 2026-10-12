package cis_windows_server_2019.security_options_test

import rego.v1

# Generated smoke test for benchmarks/cis/windows_server_2019_modular/security_options_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_security_options_validation_loads_on_empty_input if {
	m := data.cis_windows_server_2019.security_options with input as {}
	is_object(m)
}

test_security_options_validation_report_wellformed_on_empty_input if {
	report := data.cis_windows_server_2019.security_options.report with input as {}
	is_object(report)
	count(report) > 0
}

test_security_options_validation_fail_closed_on_empty_input if {
	report := data.cis_windows_server_2019.security_options.report with input as {}
	not object.get(report, "compliant", false) == true
}

test_security_options_validation_violations_on_empty_input if {
	v := data.cis_windows_server_2019.security_options.violations with input as {}
	count(v) > 0
}
