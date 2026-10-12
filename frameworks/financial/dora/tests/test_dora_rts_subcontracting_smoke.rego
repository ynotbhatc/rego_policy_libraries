package dora.rts_subcontracting_test

import rego.v1

# Generated smoke test for frameworks/financial/dora/dora_rts_subcontracting.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_dora_rts_subcontracting_loads_on_empty_input if {
	m := data.dora.rts_subcontracting with input as {}
	is_object(m)
}

test_dora_rts_subcontracting_report_wellformed_on_empty_input if {
	report := data.dora.rts_subcontracting.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_dora_rts_subcontracting_fail_closed_on_empty_input if {
	report := data.dora.rts_subcontracting.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
