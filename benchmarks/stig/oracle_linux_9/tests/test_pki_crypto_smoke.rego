package stig.oracle_linux_9.pki_crypto_test

import rego.v1

# Generated smoke test for benchmarks/stig/oracle_linux_9/pki_crypto.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_pki_crypto_loads_on_empty_input if {
	m := data.stig.oracle_linux_9.pki_crypto with input as {}
	is_object(m)
}

test_pki_crypto_report_wellformed_on_empty_input if {
	report := data.stig.oracle_linux_9.pki_crypto.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_pki_crypto_fail_closed_on_empty_input if {
	report := data.stig.oracle_linux_9.pki_crypto.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_pki_crypto_violations_on_empty_input if {
	v := data.stig.oracle_linux_9.pki_crypto.violations with input as {}
	count(v) > 0
}
