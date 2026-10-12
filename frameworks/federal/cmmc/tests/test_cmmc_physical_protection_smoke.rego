package cmmc.physical_protection_test

import rego.v1

# Generated smoke test for frameworks/federal/cmmc/cmmc_physical_protection.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cmmc_physical_protection_loads_on_empty_input if {
	m := data.cmmc.physical_protection with input as {}
	is_object(m)
}

test_cmmc_physical_protection_report_wellformed_on_empty_input if {
	report := data.cmmc.physical_protection.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cmmc_physical_protection_fail_closed_on_empty_input if {
	report := data.cmmc.physical_protection.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
