package pci_dss.secure_development.requirement_6_test

import rego.v1

# Generated smoke test for frameworks/financial/pci_dss/secure_development/requirement_6.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_requirement_6_loads_on_empty_input if {
	m := data.pci_dss.secure_development.requirement_6 with input as {}
	is_object(m)
}
