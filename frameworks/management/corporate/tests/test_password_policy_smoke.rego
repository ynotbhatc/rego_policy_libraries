package corporate.password_test

import rego.v1

# Generated smoke test for frameworks/management/corporate/password_policy.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_password_policy_loads_on_empty_input if {
	m := data.corporate.password with input as {}
	is_object(m)
}
