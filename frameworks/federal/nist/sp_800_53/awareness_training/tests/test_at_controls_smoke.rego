package nist.sp800_53.awareness_training_test

import rego.v1

# Generated smoke test for frameworks/federal/nist/sp_800_53/awareness_training/at_controls.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_at_controls_loads_on_empty_input if {
	m := data.nist.sp800_53.awareness_training with input as {}
	is_object(m)
}

test_at_controls_report_wellformed_on_empty_input if {
	report := data.nist.sp800_53.awareness_training.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_at_controls_fail_closed_on_empty_input if {
	report := data.nist.sp800_53.awareness_training.compliance_report with input as {}
	object.get(report, "compliant", null) == false
}
