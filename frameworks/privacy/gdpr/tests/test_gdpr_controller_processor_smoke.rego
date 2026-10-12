package gdpr.controller_processor_test

import rego.v1

# Generated smoke test for frameworks/privacy/gdpr/gdpr_controller_processor.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_gdpr_controller_processor_loads_on_empty_input if {
	m := data.gdpr.controller_processor with input as {}
	is_object(m)
}

test_gdpr_controller_processor_report_wellformed_on_empty_input if {
	report := data.gdpr.controller_processor.report with input as {}
	is_object(report)
	count(report) > 0
}

test_gdpr_controller_processor_fail_closed_on_empty_input if {
	report := data.gdpr.controller_processor.report with input as {}
	not object.get(report, "compliant", false) == true
}
