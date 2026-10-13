package cis_amazon_linux_2023.filesystem_test

import rego.v1

# Generated smoke test for benchmarks/cis/amazon_linux_2023/filesystem_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_filesystem_validation_loads_on_empty_input if {
	m := data.cis_amazon_linux_2023.filesystem with input as {}
	is_object(m)
}

test_filesystem_validation_report_wellformed_on_empty_input if {
	report := data.cis_amazon_linux_2023.filesystem.report with input as {}
	is_object(report)
	count(report) > 0
}

test_filesystem_validation_fail_closed_on_empty_input if {
	report := data.cis_amazon_linux_2023.filesystem.report with input as {}
	not object.get(report, "compliant", false) == true
}

