package cis_azure_test

import rego.v1

# Generated smoke test for benchmarks/cis/azure/cis_azure_foundations.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_azure_foundations_loads_on_empty_input if {
	m := data.cis_azure with input as {}
	is_object(m)
}

test_cis_azure_foundations_violations_on_empty_input if {
	v := data.cis_azure.violations with input as {}
	count(v) > 0
}
