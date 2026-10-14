package cisa_ssdaf.main_test

import rego.v1

# Smoke test in the shape scripts/gen_tests.py writes (docs/TEST_GENERATION.md).

test_cisa_ssdaf_main_loads_on_empty_input if {
	m := data.cisa_ssdaf.main with input as {}
	is_object(m)
}

test_cisa_ssdaf_main_report_wellformed_on_empty_input if {
	report := data.cisa_ssdaf.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cisa_ssdaf_main_fail_closed_on_empty_input if {
	report := data.cisa_ssdaf.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_cisa_ssdaf_main_violations_on_empty_input if {
	v := data.cisa_ssdaf.main.violations with input as {}
	count(v) > 0
}
