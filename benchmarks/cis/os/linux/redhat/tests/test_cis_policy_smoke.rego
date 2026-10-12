package cis_redhat_legacy_test

import rego.v1

# Generated smoke test for benchmarks/cis/os/linux/redhat/cis_policy.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_policy_loads_on_empty_input if {
	m := data.cis_redhat_legacy with input as {}
	is_object(m)
}
