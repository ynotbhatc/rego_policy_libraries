package cis_opnsense.main_test

import rego.v1

# Empty-input smoke tests for benchmarks/cis/network_devices/opnsense/cis_opnsense_main.rego.

test_cis_opnsense_main_loads_on_empty_input if {
	m := data.cis_opnsense.main with input as {}
	is_object(m)
}

test_cis_opnsense_main_report_wellformed_on_empty_input if {
	report := data.cis_opnsense.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cis_opnsense_main_fail_closed_on_empty_input if {
	report := data.cis_opnsense.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
	some v in report.violations
	startswith(v, "FAIL-CLOSED")
}
