package cis_amazon_linux_2023.services_test

import rego.v1

# Generated smoke test for benchmarks/cis/amazon_linux_2023/service_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_service_validation_loads_on_empty_input if {
	m := data.cis_amazon_linux_2023.services with input as {}
	is_object(m)
}

test_service_validation_report_wellformed_on_empty_input if {
	report := data.cis_amazon_linux_2023.services.report with input as {}
	is_object(report)
	count(report) > 0
}

test_service_validation_fail_closed_on_empty_input if {
	report := data.cis_amazon_linux_2023.services.report with input as {}
	not object.get(report, "compliant", false) == true
}

test_service_validation_violations_on_empty_input if {
	v := data.cis_amazon_linux_2023.services.violations with input as {}
	count(v) > 0
}
