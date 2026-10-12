package swift_csp.main_test

import rego.v1

# Generated smoke test for frameworks/financial/swift_csp/swift_csp_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_swift_csp_main_loads_on_empty_input if {
	m := data.swift_csp.main with input as {}
	is_object(m)
}

test_swift_csp_main_report_wellformed_on_empty_input if {
	report := data.swift_csp.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_swift_csp_main_fail_closed_on_empty_input if {
	report := data.swift_csp.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_swift_csp_main_violations_on_empty_input if {
	v := data.swift_csp.main.violations with input as {}
	count(v) > 0
}
