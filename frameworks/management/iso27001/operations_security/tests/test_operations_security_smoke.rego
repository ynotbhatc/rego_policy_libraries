package iso27001.operations_security_test

import rego.v1

# Generated smoke test for frameworks/management/iso27001/operations_security/operations_security.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_operations_security_loads_on_empty_input if {
	m := data.iso27001.operations_security with input as {}
	is_object(m)
}
