package cmmc.identification_authentication_test

import rego.v1

# Generated smoke test for frameworks/federal/cmmc/cmmc_identification_authentication.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cmmc_identification_authentication_loads_on_empty_input if {
	m := data.cmmc.identification_authentication with input as {}
	is_object(m)
}

test_cmmc_identification_authentication_report_wellformed_on_empty_input if {
	report := data.cmmc.identification_authentication.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cmmc_identification_authentication_fail_closed_on_empty_input if {
	report := data.cmmc.identification_authentication.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
