package stig.rhel_9.main_test

import data.stig.rhel_9
import data.stig.rhel_9.main
import rego.v1

# The uniform key set every stig.<platform>.main.compliance_report emits.
expected_keys := {
	"total_controls",
	"open_findings",
	"passed_controls",
	"failed_controls",
	"compliant",
	"compliance_percentage",
	"violations",
	"violation_count",
	"facts_supplied",
}

# Phase 1 contract smoke test: the live orchestrator endpoint
# (data.stig.rhel_9.main.compliance_report) must return a well-formed
# object on empty input, never collapse to undefined or {}.
test_report_wellformed_on_empty_input if {
	report := main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
	is_boolean(report.compliant)
	object.keys(report) == expected_keys
}

# total_controls is derived from the module finding arrays, not hard-coded,
# and every one of the 9 RHEL 9 modules contributes to it.
test_total_controls_derived_from_modules if {
	report := main.compliance_report with input as {}
	report.total_controls == count(rhel_9.all_findings)
	report.total_controls > 0
}

# No facts => fully non-compliant with a zero score: never a partial pass.
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
	contains(f.rule_title, "FAIL-CLOSED: no facts supplied for stig.rhel_9")
}

# The gate must be transparent once real facts arrive: a genuine assessment
# must still score normally, not stay pinned at zero.
test_gate_transparent_when_facts_supplied if {
	report := main.compliance_report with input as {"ssh_config": {"PermitRootLogin": "no"}}
	report.facts_supplied == true
	report.compliance_percentage > 0
	report.passed_controls > 0
	not contains(concat(" ", [f.rule_title | some f in report.violations]), "FAIL-CLOSED")
}

# Seeded violation: PermitRootLogin yes must surface RHEL-09-255010 (V-257985)
# as an Open CAT I finding in the aggregated violations.
test_seeded_violation_surfaces_in_report if {
	report := main.compliance_report with input as {"ssh_config": {"PermitRootLogin": "yes"}}
	report.facts_supplied == true
	report.compliant == false
	some f in report.violations
	f.stig_id == "RHEL-09-255010"
	f.vuln_id == "V-257985"
	f.severity == "CAT I"
	f.status == "Open"
}
