package governance.oidc_test

import rego.v1

# Generated smoke test for governance/oidc/oidc_token_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_oidc_token_validation_loads_on_empty_input if {
	m := data.governance.oidc with input as {}
	is_object(m)
}
