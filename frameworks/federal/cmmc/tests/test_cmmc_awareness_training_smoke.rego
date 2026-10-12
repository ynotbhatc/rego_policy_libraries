package cmmc.awareness_training_test

import rego.v1

# Generated smoke test for frameworks/federal/cmmc/cmmc_awareness_training.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cmmc_awareness_training_loads_on_empty_input if {
	m := data.cmmc.awareness_training with input as {}
	is_object(m)
}

test_cmmc_awareness_training_report_wellformed_on_empty_input if {
	report := data.cmmc.awareness_training.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cmmc_awareness_training_fail_closed_on_empty_input if {
	report := data.cmmc.awareness_training.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
