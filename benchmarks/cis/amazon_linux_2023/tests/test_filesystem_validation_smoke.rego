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

# Semantic review 2026-11-13: a missing disabled_filesystem_modules fact must not pass.
test_missing_disabled_filesystem_modules_flagged if {
	v := data.cis_amazon_linux_2023.filesystem.filesystem_module_violations with input as {}
	"CIS 1.1.1.x: evidence missing - disabled_filesystem_modules.modules not collected" in v
}
