package iec_62443.part2_4_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/iec_62443/part2_service_provider.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_part2_service_provider_loads_on_empty_input if {
	m := data.iec_62443.part2_4 with input as {}
	is_object(m)
}

test_part2_service_provider_report_wellformed_on_empty_input if {
	report := data.iec_62443.part2_4.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_part2_service_provider_fail_closed_on_empty_input if {
	report := data.iec_62443.part2_4.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_part2_service_provider_violations_on_empty_input if {
	v := data.iec_62443.part2_4.violations with input as {}
	count(v) > 0
}
