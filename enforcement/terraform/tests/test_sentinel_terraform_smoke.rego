package sentinel.terraform_test

import rego.v1

# Generated smoke test for enforcement/terraform/sentinel_terraform.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_sentinel_terraform_loads_on_empty_input if {
	m := data.sentinel.terraform with input as {}
	is_object(m)
}

