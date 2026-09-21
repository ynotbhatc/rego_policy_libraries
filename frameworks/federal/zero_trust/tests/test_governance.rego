package zero_trust.governance_test

import rego.v1

import data.zero_trust.governance

# Build an input that attests every criterion as true.
all_true := {"zero_trust": {"governance": {"criteria": {id: true |
	some id, _ in governance.criteria
}}}}

# Empty attestation → every criterion fires a violation and capability is not compliant.
test_empty_input_all_fire if {
	inp := {"zero_trust": {"governance": {"criteria": {}}}}
	count(governance.violation) == count(governance.criteria) with input as inp
	not governance.pillar_compliant with input as inp
}

# Fully attested → no violations and capability is compliant.
test_all_attested_compliant if {
	count(governance.violation) == 0 with input as all_true
	governance.pillar_compliant with input as all_true
}

# Flipping a single criterion to false yields exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true, {"zero_trust": {"governance": {"criteria": {"GOV-4": false}}}})
	count(governance.violation) == 1 with input as flipped
	not governance.pillar_compliant with input as flipped
	some msg in governance.violation with input as flipped
	contains(msg, "GOV-4") with input as flipped
}

# Report is populated on empty input.
test_report_populated_on_empty if {
	inp := {"zero_trust": {"governance": {"criteria": {}}}}
	report := governance.compliance_report with input as inp
	report.pillar == "Governance"
	report.criteria_evaluated == count(governance.criteria)
	report.violation_count == count(governance.criteria)
	report.compliant == false
}
