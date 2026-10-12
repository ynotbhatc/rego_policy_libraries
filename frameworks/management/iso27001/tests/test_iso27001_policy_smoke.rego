package iso27001_test

import rego.v1

# Generated smoke test for frameworks/management/iso27001/iso27001_policy.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_iso27001_policy_loads_on_empty_input if {
	m := data.iso27001 with input as {}
	is_object(m)
}
