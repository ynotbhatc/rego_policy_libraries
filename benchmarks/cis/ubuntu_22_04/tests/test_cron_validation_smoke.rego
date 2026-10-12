package cis_ubuntu_22_04.cron_test

import rego.v1

# Generated smoke test for benchmarks/cis/ubuntu_22_04/cron_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cron_validation_loads_on_empty_input if {
	m := data.cis_ubuntu_22_04.cron with input as {}
	is_object(m)
}

test_cron_validation_report_wellformed_on_empty_input if {
	report := data.cis_ubuntu_22_04.cron.report with input as {}
	is_object(report)
	count(report) > 0
}

test_cron_validation_fail_closed_on_empty_input if {
	report := data.cis_ubuntu_22_04.cron.report with input as {}
	not object.get(report, "compliant", false) == true
}

test_cron_validation_violations_on_empty_input if {
	v := data.cis_ubuntu_22_04.cron.violations with input as {}
	count(v) > 0
}
