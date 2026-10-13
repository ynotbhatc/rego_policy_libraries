package stig.oracle_database_19c.core_test

import rego.v1

# Generated smoke test for benchmarks/stig/oracle_database_19c/core.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_core_loads_on_empty_input if {
	m := data.stig.oracle_database_19c.core with input as {}
	is_object(m)
}

test_core_fail_closed_on_empty_input if {
	not data.stig.oracle_database_19c.core.compliant with input as {}
}
