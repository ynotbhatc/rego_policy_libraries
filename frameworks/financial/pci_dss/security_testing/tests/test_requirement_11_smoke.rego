package pci_dss.security_testing.requirement_11_test

import rego.v1

# Generated smoke test for frameworks/financial/pci_dss/security_testing/requirement_11.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_requirement_11_loads_on_empty_input if {
	m := data.pci_dss.security_testing.requirement_11 with input as {}
	is_object(m)
}
