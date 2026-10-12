package tsa_pipeline.sd01_reporting_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/tsa_pipeline/sd01_incident_reporting.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_sd01_incident_reporting_loads_on_empty_input if {
	m := data.tsa_pipeline.sd01_reporting with input as {}
	is_object(m)
}

test_sd01_incident_reporting_report_wellformed_on_empty_input if {
	report := data.tsa_pipeline.sd01_reporting.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_sd01_incident_reporting_fail_closed_on_empty_input if {
	report := data.tsa_pipeline.sd01_reporting.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_sd01_incident_reporting_violations_on_empty_input if {
	v := data.tsa_pipeline.sd01_reporting.violations with input as {}
	count(v) > 0
}
