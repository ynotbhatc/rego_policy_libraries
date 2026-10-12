package digital_sovereignty.cryptographic_sovereignty_test

import rego.v1

# Generated smoke test for frameworks/sovereignty/digital_sovereignty/cryptographic_sovereignty.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cryptographic_sovereignty_loads_on_empty_input if {
	m := data.digital_sovereignty.cryptographic_sovereignty with input as {}
	is_object(m)
}

test_cryptographic_sovereignty_report_wellformed_on_empty_input if {
	report := data.digital_sovereignty.cryptographic_sovereignty.report with input as {}
	is_object(report)
	count(report) > 0
}

test_cryptographic_sovereignty_fail_closed_on_empty_input if {
	report := data.digital_sovereignty.cryptographic_sovereignty.report with input as {}
	not object.get(report, "compliant", false) == true
}

test_cryptographic_sovereignty_violations_on_empty_input if {
	v := data.digital_sovereignty.cryptographic_sovereignty.violations with input as {}
	count(v) > 0
}
