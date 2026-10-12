package ny_dfs.main_test

import rego.v1

# Generated smoke test for frameworks/financial/ny_dfs/ny_dfs_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_ny_dfs_main_loads_on_empty_input if {
	m := data.ny_dfs.main with input as {}
	is_object(m)
}

test_ny_dfs_main_report_wellformed_on_empty_input if {
	report := data.ny_dfs.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_ny_dfs_main_fail_closed_on_empty_input if {
	report := data.ny_dfs.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_ny_dfs_main_violations_on_empty_input if {
	v := data.ny_dfs.main.violations with input as {}
	count(v) > 0
}
