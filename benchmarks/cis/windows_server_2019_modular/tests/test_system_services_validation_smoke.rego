package cis_windows_server_2019.system_services_test

import rego.v1

# Generated smoke test for benchmarks/cis/windows_server_2019_modular/system_services_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_system_services_validation_loads_on_empty_input if {
	m := data.cis_windows_server_2019.system_services with input as {}
	is_object(m)
}

test_system_services_validation_report_wellformed_on_empty_input if {
	report := data.cis_windows_server_2019.system_services.report with input as {}
	is_object(report)
	count(report) > 0
}

test_system_services_validation_fail_closed_on_empty_input if {
	report := data.cis_windows_server_2019.system_services.report with input as {}
	not object.get(report, "compliant", false) == true
}

