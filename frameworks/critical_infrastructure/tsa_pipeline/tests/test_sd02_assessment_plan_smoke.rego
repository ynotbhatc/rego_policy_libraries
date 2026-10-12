package tsa_pipeline.sd02_assessment_plan_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/tsa_pipeline/sd02_assessment_plan.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_sd02_assessment_plan_loads_on_empty_input if {
	m := data.tsa_pipeline.sd02_assessment_plan with input as {}
	is_object(m)
}

test_sd02_assessment_plan_report_wellformed_on_empty_input if {
	report := data.tsa_pipeline.sd02_assessment_plan.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_sd02_assessment_plan_fail_closed_on_empty_input if {
	report := data.tsa_pipeline.sd02_assessment_plan.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_sd02_assessment_plan_violations_on_empty_input if {
	v := data.tsa_pipeline.sd02_assessment_plan.violations with input as {}
	count(v) > 0
}
