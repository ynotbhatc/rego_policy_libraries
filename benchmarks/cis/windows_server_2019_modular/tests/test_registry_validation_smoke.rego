package cis_windows_server_2019.registry_test

import rego.v1

# Generated smoke test for benchmarks/cis/windows_server_2019_modular/registry_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_registry_validation_loads_on_empty_input if {
	m := data.cis_windows_server_2019.registry with input as {}
	is_object(m)
}

test_registry_validation_report_wellformed_on_empty_input if {
	report := data.cis_windows_server_2019.registry.report with input as {}
	is_object(report)
	count(report) > 0
}

test_registry_validation_fail_closed_on_empty_input if {
	report := data.cis_windows_server_2019.registry.report with input as {}
	not object.get(report, "compliant", false) == true
}

test_registry_validation_violations_on_empty_input if {
	v := data.cis_windows_server_2019.registry.violations with input as {}
	count(v) > 0
}
