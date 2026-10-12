package iso27701.main_test

import rego.v1

# Generated smoke test for frameworks/privacy/iso27701/iso27701_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_iso27701_main_loads_on_empty_input if {
	m := data.iso27701.main with input as {}
	is_object(m)
}

test_iso27701_main_report_wellformed_on_empty_input if {
	report := data.iso27701.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_iso27701_main_fail_closed_on_empty_input if {
	report := data.iso27701.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
