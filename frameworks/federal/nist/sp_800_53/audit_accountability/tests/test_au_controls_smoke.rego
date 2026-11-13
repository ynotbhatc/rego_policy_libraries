package nist.sp800_53.audit_accountability_test

import rego.v1

# Generated smoke test for frameworks/federal/nist/sp_800_53/audit_accountability/au_controls.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_au_controls_loads_on_empty_input if {
	m := data.nist.sp800_53.audit_accountability with input as {}
	is_object(m)
}

test_au_controls_report_wellformed_on_empty_input if {
	report := data.nist.sp800_53.audit_accountability.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_au_controls_fail_closed_on_empty_input if {
	report := data.nist.sp800_53.audit_accountability.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# semantic review 2026-11-13: AU-11 must fire when au_controls is absent altogether.
test_review_au11_fires_without_au_controls_block if {
	r := data.nist.sp800_53.audit_accountability.compliance_report with input as {}
	some v in r.violations
	startswith(v, "NIST AU-11:")
	r.violation_count == 12
}
