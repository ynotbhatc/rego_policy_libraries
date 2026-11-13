package stig.rhel_10.account_auth_test

import rego.v1

# Generated smoke test for benchmarks/stig/rhel_10/account_auth.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_account_auth_loads_on_empty_input if {
	m := data.stig.rhel_10.account_auth with input as {}
	is_object(m)
}

test_account_auth_report_wellformed_on_empty_input if {
	report := data.stig.rhel_10.account_auth.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_account_auth_fail_closed_on_empty_input if {
	report := data.stig.rhel_10.account_auth.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_account_auth_violations_on_empty_input if {
	v := data.stig.rhel_10.account_auth.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: missing evidence must not pass.

test_missing_evidence_open_status_rhel_10_600460 if {
	data.stig.rhel_10.account_auth.status_rhel_10_600460 == "Open" with input as {"x": 1}
}

test_missing_evidence_open_status_rhel_10_600130 if {
	data.stig.rhel_10.account_auth.status_rhel_10_600130 == "Open" with input as {"x": 1}
}

test_missing_evidence_open_status_rhel_10_600470 if {
	data.stig.rhel_10.account_auth.status_rhel_10_600470 == "Open" with input as {"x": 1}
}
