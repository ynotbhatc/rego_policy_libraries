package cmmc.audit_accountability_test

import rego.v1

# Generated smoke test for frameworks/federal/cmmc/cmmc_audit_accountability.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cmmc_audit_accountability_loads_on_empty_input if {
	m := data.cmmc.audit_accountability with input as {}
	is_object(m)
}

test_cmmc_audit_accountability_report_wellformed_on_empty_input if {
	report := data.cmmc.audit_accountability.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cmmc_audit_accountability_fail_closed_on_empty_input if {
	report := data.cmmc.audit_accountability.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
