package cis_rhel9.cron_test

import rego.v1

# Generated smoke test for benchmarks/cis/rhel_9/cron_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cron_validation_loads_on_empty_input if {
	m := data.cis_rhel9.cron with input as {}
	is_object(m)
}

test_cron_validation_violations_on_empty_input if {
	v := data.cis_rhel9.cron.violations with input as {}
	count(v) > 0
}
