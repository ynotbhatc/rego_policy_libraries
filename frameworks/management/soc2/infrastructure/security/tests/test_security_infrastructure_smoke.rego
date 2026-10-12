package soc2.infrastructure.security_test

import rego.v1

# Generated smoke test for frameworks/management/soc2/infrastructure/security/security_infrastructure.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_security_infrastructure_loads_on_empty_input if {
	m := data.soc2.infrastructure.security with input as {}
	is_object(m)
}
