package cis_ubuntu_22_04.pam_test

import rego.v1

# Generated smoke test for benchmarks/cis/ubuntu_22_04/pam_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_pam_validation_loads_on_empty_input if {
	m := data.cis_ubuntu_22_04.pam with input as {}
	is_object(m)
}

test_pam_validation_report_wellformed_on_empty_input if {
	report := data.cis_ubuntu_22_04.pam.report with input as {}
	is_object(report)
	count(report) > 0
}

test_pam_validation_fail_closed_on_empty_input if {
	report := data.cis_ubuntu_22_04.pam.report with input as {}
	not object.get(report, "compliant", false) == true
}

