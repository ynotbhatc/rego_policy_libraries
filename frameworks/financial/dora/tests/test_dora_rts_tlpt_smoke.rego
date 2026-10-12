package dora.rts_tlpt_test

import rego.v1

# Generated smoke test for frameworks/financial/dora/dora_rts_tlpt.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_dora_rts_tlpt_loads_on_empty_input if {
	m := data.dora.rts_tlpt with input as {}
	is_object(m)
}

test_dora_rts_tlpt_report_wellformed_on_empty_input if {
	report := data.dora.rts_tlpt.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_dora_rts_tlpt_fail_closed_on_empty_input if {
	report := data.dora.rts_tlpt.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
