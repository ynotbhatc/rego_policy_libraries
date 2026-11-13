package cra.incident_reporting_test

import rego.v1

# Generated smoke test for frameworks/compliance/cra/incident_reporting/cra_incident_reporting.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cra_incident_reporting_loads_on_empty_input if {
	m := data.cra.incident_reporting with input as {}
	is_object(m)
}

test_cra_incident_reporting_report_wellformed_on_empty_input if {
	report := data.cra.incident_reporting.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cra_incident_reporting_fail_closed_on_empty_input if {
	report := data.cra.incident_reporting.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# Semantic review 2026-11-13: unsent early warning with no timing evidence must raise a finding.
test_exploited_vuln_without_timing_evidence_raises_finding if {
	v := data.cra.incident_reporting.violation with input as {"incident_reporting": {"actively_exploited_vuln_known": true, "early_warning_sent": false}}
	some m in v
	startswith(m, "CRA Art.14(2)(a): evidence missing")
}

test_severe_incident_without_timing_evidence_raises_finding if {
	v := data.cra.incident_reporting.violation with input as {"incident_reporting": {"severe_incident_occurred": true, "incident_early_warning_sent": false}}
	some m in v
	startswith(m, "CRA Art.14(4)(a): evidence missing")
}
