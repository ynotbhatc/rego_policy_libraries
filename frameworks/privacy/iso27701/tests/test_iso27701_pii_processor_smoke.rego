package iso27701.pii_processor_test

import rego.v1

# Generated smoke test for frameworks/privacy/iso27701/iso27701_pii_processor.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_iso27701_pii_processor_loads_on_empty_input if {
	m := data.iso27701.pii_processor with input as {}
	is_object(m)
}

test_iso27701_pii_processor_report_wellformed_on_empty_input if {
	report := data.iso27701.pii_processor.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_iso27701_pii_processor_fail_closed_on_empty_input if {
	report := data.iso27701.pii_processor.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_iso27701_pii_processor_violations_on_empty_input if {
	v := data.iso27701.pii_processor.violations with input as {}
	count(v) > 0
}
