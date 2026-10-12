package stig.ubuntu_22_04.main_test

import rego.v1

# Generated smoke test for benchmarks/stig/ubuntu_22_04/stig_ubuntu_22_04_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_stig_ubuntu_22_04_main_loads_on_empty_input if {
	m := data.stig.ubuntu_22_04.main with input as {}
	is_object(m)
}

test_stig_ubuntu_22_04_main_report_wellformed_on_empty_input if {
	report := data.stig.ubuntu_22_04.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_stig_ubuntu_22_04_main_fail_closed_on_empty_input if {
	report := data.stig.ubuntu_22_04.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_stig_ubuntu_22_04_main_violations_on_empty_input if {
	v := data.stig.ubuntu_22_04.main.violations with input as {}
	count(v) > 0
}
