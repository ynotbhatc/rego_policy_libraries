package pci_dss.main_test

import rego.v1

# Generated smoke test for frameworks/financial/pci_dss/pci_dss_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_pci_dss_main_loads_on_empty_input if {
	m := data.pci_dss.main with input as {}
	is_object(m)
}

# Semantic review 2026-11-13: compliance_report.compliant must agree with overall_pci_dss_compliant.
test_semrev_report_not_compliant_when_cde_scope_undocumented if {
	r := data.pci_dss.main.compliance_report with input as {}
		with data.pci_dss.main.requirement_1_compliant as true
		with data.pci_dss.main.requirement_2_compliant as true
		with data.pci_dss.main.requirement_3_compliant as true
		with data.pci_dss.main.requirement_4_compliant as true
		with data.pci_dss.main.requirement_5_compliant as true
		with data.pci_dss.main.requirement_6_compliant as true
		with data.pci_dss.main.requirement_7_compliant as true
		with data.pci_dss.main.requirement_8_compliant as true
		with data.pci_dss.main.requirement_9_compliant as true
		with data.pci_dss.main.requirement_10_compliant as true
		with data.pci_dss.main.requirement_11_compliant as true
		with data.pci_dss.main.requirement_12_compliant as true
	r.compliant == false
	r.violation_count == 2
	r.failed_controls <= r.total_controls
}

# Audit 2026-11-17: the family reports the version in force; v4.0 is retired.
test_report_names_v4_0_1 if {
	r := data.pci_dss.main.compliance_report with input as {}
	r.standard == "PCI DSS v4.0.1"
	r.compliant == false
	r.total_controls == 12
	r.failed_controls <= r.total_controls
}

test_string_transaction_volume_is_unknown_level if {
	data.pci_dss.main.pci_validation_level == "Unknown" with input as {"pci": {"transaction_volume": {"annual": "9000000"}}}
}

test_numeric_transaction_volume_level if {
	data.pci_dss.main.pci_validation_level == "Level 1" with input as {"pci": {"transaction_volume": {"annual": 9000000}}}
}
