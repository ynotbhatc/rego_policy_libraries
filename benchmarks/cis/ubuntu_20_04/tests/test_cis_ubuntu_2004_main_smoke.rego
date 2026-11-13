package cis_ubuntu_20_04.main_test

import rego.v1

# Generated smoke test for benchmarks/cis/ubuntu_20_04/cis_ubuntu_2004_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_ubuntu_2004_main_loads_on_empty_input if {
	m := data.cis_ubuntu_20_04.main with input as {}
	is_object(m)
}

test_cis_ubuntu_2004_main_report_wellformed_on_empty_input if {
	report := data.cis_ubuntu_20_04.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cis_ubuntu_2004_main_fail_closed_on_empty_input if {
	report := data.cis_ubuntu_20_04.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# Semantic review 2026-11-13: failed_controls counts distinct control ids, not violation messages.
test_failed_controls_counts_distinct_control_ids if {
	report := data.cis_ubuntu_20_04.main.compliance_report with input as {"x": 1}
		with data.cis_ubuntu_20_04.violations as ["CIS 5.2.1: first finding", "CIS 5.2.1: second finding", "CIS 5.2.2: other control"]
	report.failed_controls == 2
}
