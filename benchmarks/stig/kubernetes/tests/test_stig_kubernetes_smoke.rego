package stig_kubernetes.main_test

import data.stig_kubernetes.main
import rego.v1

# Phase 1 contract smoke test: the live orchestrator endpoint
# (data.stig_kubernetes.main.compliance_report) must return a well-formed
# object on empty input, never collapse to undefined.
test_report_wellformed_on_empty_input if {
	report := main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
	is_boolean(report.compliant)
}

# Well-formedness alone is not enough. Before the fail-closed gate this report
# was well-formed and `compliant` was already false — but the score was 86%
# with 25 of 29 controls counted as PASSED on empty input. Asserting only the
# boolean is what let that through, so assert the score too.
test_fails_closed_on_empty_input if {
	report := main.compliance_report with input as {}
	report.compliant == false
	report.facts_supplied == false
	report.compliance_percentage == 0
	report.passed_controls == 0
	report.failed_controls == report.total_controls
	report.violation_count > 0
}

test_no_facts_finding_is_explicit if {
	report := main.compliance_report with input as {}
	some f in report.violations
	contains(f.rule_title, "FAIL-CLOSED: no facts supplied for stig_kubernetes")
}

# The gate must be transparent once real facts arrive — a genuine assessment
# must still score normally, not stay pinned at zero.
test_gate_transparent_when_facts_supplied if {
	report := main.compliance_report with input as {"kube_apiserver": {"anonymous_auth": false}}
	report.facts_supplied == true
	report.compliance_percentage > 0
	report.passed_controls > 0
	not contains(concat(" ", [f.rule_title | some f in report.violations]), "FAIL-CLOSED")
}
