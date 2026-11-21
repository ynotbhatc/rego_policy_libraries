package pci_dss.main_numeric_guards_test

import rego.v1

# "7000000" sorts above every number; a non-numeric volume gives "Unknown", never a merchant level.
test_string_volume_is_unknown if {
	data.pci_dss.main.pci_validation_level == "Unknown" with input as {"pci": {"transaction_volume": {"annual": "1"}}}
}

test_null_volume_is_unknown if {
	data.pci_dss.main.pci_validation_level == "Unknown" with input as {"pci": {"transaction_volume": {"annual": null}}}
}

test_text_volume_is_unknown if {
	data.pci_dss.main.pci_validation_level == "Unknown" with input as {"pci": {"transaction_volume": {"annual": "x"}}}
}

test_numeric_volume_unchanged if {
	data.pci_dss.main.pci_validation_level == "Level 1" with input as {"pci": {"transaction_volume": {"annual": 7000000}}}
	data.pci_dss.main.pci_validation_level == "Level 4" with input as {"pci": {"transaction_volume": {"annual": 100}}}
}
