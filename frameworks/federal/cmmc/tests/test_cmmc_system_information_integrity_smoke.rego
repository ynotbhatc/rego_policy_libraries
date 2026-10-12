package cmmc.system_information_integrity_test

import rego.v1

# Generated smoke test for frameworks/federal/cmmc/cmmc_system_information_integrity.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cmmc_system_information_integrity_loads_on_empty_input if {
	m := data.cmmc.system_information_integrity with input as {}
	is_object(m)
}

test_cmmc_system_information_integrity_report_wellformed_on_empty_input if {
	report := data.cmmc.system_information_integrity.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cmmc_system_information_integrity_fail_closed_on_empty_input if {
	report := data.cmmc.system_information_integrity.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
