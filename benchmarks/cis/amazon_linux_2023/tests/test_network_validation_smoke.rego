package cis_amazon_linux_2023.network_test

import rego.v1

# Generated smoke test for benchmarks/cis/amazon_linux_2023/network_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_network_validation_loads_on_empty_input if {
	m := data.cis_amazon_linux_2023.network with input as {}
	is_object(m)
}

test_network_validation_report_wellformed_on_empty_input if {
	report := data.cis_amazon_linux_2023.network.report with input as {}
	is_object(report)
	count(report) > 0
}

