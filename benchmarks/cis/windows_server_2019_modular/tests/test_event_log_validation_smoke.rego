package cis_windows_server_2019.event_log_test

import rego.v1

# Generated smoke test for benchmarks/cis/windows_server_2019_modular/event_log_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_event_log_validation_loads_on_empty_input if {
	m := data.cis_windows_server_2019.event_log with input as {}
	is_object(m)
}

test_event_log_validation_violations_on_empty_input if {
	v := data.cis_windows_server_2019.event_log.violations with input as {}
	count(v) > 0
}
