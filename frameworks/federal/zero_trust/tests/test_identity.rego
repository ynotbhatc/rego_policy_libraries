package zero_trust.identity_test

import rego.v1

import data.zero_trust.identity

# Build an input that attests every criterion as true.
all_true := {"zero_trust": {"identity": {"criteria": all_criteria}}} if {
	all_criteria := {id: true | some id, _ in identity.criteria}
}

# Empty input -> every criterion fires as a violation and the pillar is not compliant.
test_empty_input_all_fire if {
	count(identity.violation) == count(identity.criteria) with input as {}
	count(identity.violation) > 0 with input as {}
	not identity.pillar_compliant with input as {}
}

# Fully attested -> no violations and the pillar is compliant.
test_all_attested_compliant if {
	count(identity.violation) == 0 with input as all_true
	identity.pillar_compliant with input as all_true
}

# Flip a single criterion to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := object.union(all_true, {"zero_trust": {"identity": {"criteria": object.union(all_true.zero_trust.identity.criteria, {"ID-2": false})}}})
	count(identity.violation) == 1 with input as broken
	some msg in identity.violation with input as broken
	contains(msg, "ID-2") with input as broken
}

# A missing (not present) criterion also fires, fail-closed.
test_missing_key_fails_closed if {
	partial := {"zero_trust": {"identity": {"criteria": {"ID-1": true}}}}
	count(identity.violation) == count(identity.criteria) - 1 with input as partial
	not identity.pillar_compliant with input as partial
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := identity.compliance_report with input as {}
	report.pillar == "Identity"
	report.criteria_evaluated == count(identity.criteria)
	report.violation_count == count(identity.criteria)
	report.compliant == false
}
