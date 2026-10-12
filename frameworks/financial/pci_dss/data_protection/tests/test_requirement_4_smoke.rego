package pci_dss.data_protection.requirement_4_test

import rego.v1

# Generated smoke test for frameworks/financial/pci_dss/data_protection/requirement_4.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_requirement_4_loads_on_empty_input if {
	m := data.pci_dss.data_protection.requirement_4 with input as {}
	is_object(m)
}
