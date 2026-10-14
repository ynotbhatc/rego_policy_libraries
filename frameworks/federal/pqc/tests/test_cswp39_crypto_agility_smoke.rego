package pqc.cswp39_test

import rego.v1

# Generated smoke test for frameworks/federal/pqc/cswp39_crypto_agility.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cswp39_crypto_agility_loads_on_empty_input if {
	m := data.pqc.cswp39 with input as {}
	is_object(m)
}

test_cswp39_crypto_agility_report_wellformed_on_empty_input if {
	report := data.pqc.cswp39.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cswp39_crypto_agility_fail_closed_on_empty_input if {
	report := data.pqc.cswp39.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_cswp39_crypto_agility_violations_on_empty_input if {
	v := data.pqc.cswp39.violations with input as {}
	count(v) > 0
}
