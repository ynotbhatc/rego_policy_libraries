package cmmc.risk_assessment_test

import rego.v1

# Generated smoke test for frameworks/federal/cmmc/cmmc_risk_assessment.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cmmc_risk_assessment_loads_on_empty_input if {
	m := data.cmmc.risk_assessment with input as {}
	is_object(m)
}

test_cmmc_risk_assessment_report_wellformed_on_empty_input if {
	report := data.cmmc.risk_assessment.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cmmc_risk_assessment_fail_closed_on_empty_input if {
	report := data.cmmc.risk_assessment.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# --- semantic review 2026-11-13: domain verdict must agree with practices ---

good_input_review := {"risk": {"risk_assessment_conducted": true, "risk_assessment_frequency_days": 365, "risk_assessment_documented": true, "vulnerability_scanning_enabled": true, "scan_frequency_days": 30, "scan_results_reviewed": true, "new_vuln_scan_triggered": true, "vuln_remediation_policy": true, "critical_vuln_remediation_days": 15, "high_vuln_remediation_days": 30, "remediation_tracked": true}}

test_review_good_input_compliant if {
	r := data.cmmc.risk_assessment.compliance_report with input as good_input_review
	r.compliant
	r.failing == 0
}

test_review_scan_frequency_missing if {
	r := data.cmmc.risk_assessment.compliance_report with input as {"risk": {"risk_assessment_conducted": true, "risk_assessment_frequency_days": 365, "risk_assessment_documented": true, "vulnerability_scanning_enabled": true, "scan_results_reviewed": true, "new_vuln_scan_triggered": true, "vuln_remediation_policy": true, "critical_vuln_remediation_days": 15, "high_vuln_remediation_days": 30, "remediation_tracked": true}}
	r.failing > 0
	not r.compliant
	count(r.violations) > 0
	some v in r.violations
	startswith(v, "3.11.")
}
