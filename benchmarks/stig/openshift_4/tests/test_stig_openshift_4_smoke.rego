package stig.openshift_4.main_test

import data.stig.openshift_4.main
import rego.v1

# Phase 1 contract smoke test: the live orchestrator endpoint
# (data.stig.openshift_4.main.compliance_report) must return a well-formed
# object on empty input, never collapse to undefined.
test_report_wellformed_on_empty_input if {
	report := main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
	is_boolean(report.compliant)
}

# Well-formedness alone is not enough: before the fail-closed gate this report
# was well-formed AND claimed compliant=true at 100% (24/24 passed) on empty
# input. A bogus PASS reaches a downstream results store as a green row, which is worse
# than a report that collapses to {} (the playbook fails on that one).
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
	contains(f.rule_title, "FAIL-CLOSED: no facts supplied for stig.openshift_4")
}

# The gate must be transparent once real facts arrive — it must not permanently
# pin the score to zero.
test_gate_transparent_when_facts_supplied if {
	report := main.compliance_report with input as {"openshift": {"fips_mode": true}}
	report.facts_supplied == true
	not contains(concat(" ", [f.rule_title | some f in report.violations]), "FAIL-CLOSED")
}
