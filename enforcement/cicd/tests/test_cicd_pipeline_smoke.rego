package cicd.pipeline_test

import rego.v1

# Generated smoke test for enforcement/cicd/cicd_pipeline.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cicd_pipeline_loads_on_empty_input if {
	m := data.cicd.pipeline with input as {}
	is_object(m)
}

test_cicd_pipeline_report_wellformed_on_empty_input if {
	report := data.cicd.pipeline.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

