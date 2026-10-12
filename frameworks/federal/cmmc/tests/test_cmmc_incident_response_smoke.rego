package cmmc.incident_response_test

import rego.v1

# Generated smoke test for frameworks/federal/cmmc/cmmc_incident_response.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cmmc_incident_response_loads_on_empty_input if {
	m := data.cmmc.incident_response with input as {}
	is_object(m)
}

test_cmmc_incident_response_report_wellformed_on_empty_input if {
	report := data.cmmc.incident_response.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cmmc_incident_response_fail_closed_on_empty_input if {
	report := data.cmmc.incident_response.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_cmmc_incident_response_violations_on_empty_input if {
	v := data.cmmc.incident_response.violations with input as {}
	count(v) > 0
}
