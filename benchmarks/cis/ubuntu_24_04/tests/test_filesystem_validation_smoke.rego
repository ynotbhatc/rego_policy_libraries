package cis_ubuntu_24_04.filesystem_test

import rego.v1

# Generated smoke test for benchmarks/cis/ubuntu_24_04/filesystem_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_filesystem_validation_loads_on_empty_input if {
	m := data.cis_ubuntu_24_04.filesystem with input as {}
	is_object(m)
}

test_filesystem_validation_report_wellformed_on_empty_input if {
	report := data.cis_ubuntu_24_04.filesystem.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

