package zero_trust.automation_orchestration_test

import rego.v1

import data.zero_trust.automation_orchestration

# Build an input that attests every criterion as true.
all_true := {"zero_trust": {"automation_orchestration": {"criteria": {id: true |
	some id, _ in automation_orchestration.criteria
}}}}

# Empty attestation → every criterion fires a violation and capability is not compliant.
test_empty_input_all_fire if {
	inp := {"zero_trust": {"automation_orchestration": {"criteria": {}}}}
	count(automation_orchestration.violation) == count(automation_orchestration.criteria) with input as inp
	not automation_orchestration.pillar_compliant with input as inp
}

# Fully attested → no violations and capability is compliant.
test_all_attested_compliant if {
	count(automation_orchestration.violation) == 0 with input as all_true
	automation_orchestration.pillar_compliant with input as all_true
}

# Flipping a single criterion to false yields exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true, {"zero_trust": {"automation_orchestration": {"criteria": {"AUT-3": false}}}})
	count(automation_orchestration.violation) == 1 with input as flipped
	not automation_orchestration.pillar_compliant with input as flipped
	some msg in automation_orchestration.violation with input as flipped
	contains(msg, "AUT-3") with input as flipped
}

# Report is populated on empty input.
test_report_populated_on_empty if {
	inp := {"zero_trust": {"automation_orchestration": {"criteria": {}}}}
	report := automation_orchestration.compliance_report with input as inp
	report.pillar == "Automation & Orchestration"
	report.criteria_evaluated == count(automation_orchestration.criteria)
	report.violation_count == count(automation_orchestration.criteria)
	report.compliant == false
}
