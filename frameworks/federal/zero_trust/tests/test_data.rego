package zero_trust.data_test

import rego.v1

import data.zero_trust.data

# Build an input that attests every criterion as true.
all_true := {"zero_trust": {"data": {"criteria": all_criteria}}} if {
	all_criteria := {id: true | some id, _ in data.criteria}
}

# Empty input -> every criterion fires as a violation and the pillar is not compliant.
test_empty_input_all_fire if {
	count(data.violation) == count(data.criteria) with input as {}
	count(data.violation) > 0 with input as {}
	not data.pillar_compliant with input as {}
}

# Fully attested -> no violations and the pillar is compliant.
test_all_attested_compliant if {
	count(data.violation) == 0 with input as all_true
	data.pillar_compliant with input as all_true
}

# Flip a single criterion to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := object.union(all_true, {"zero_trust": {"data": {"criteria": object.union(all_true.zero_trust.data.criteria, {"DATA-7": false})}}})
	count(data.violation) == 1 with input as broken
	some msg in data.violation with input as broken
	contains(msg, "DATA-7") with input as broken
}

# A missing (not present) criterion also fires, fail-closed.
test_missing_key_fails_closed if {
	partial := {"zero_trust": {"data": {"criteria": {"DATA-1": true}}}}
	count(data.violation) == count(data.criteria) - 1 with input as partial
	not data.pillar_compliant with input as partial
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := data.compliance_report with input as {}
	report.pillar == "Data"
	report.criteria_evaluated == count(data.criteria)
	report.violation_count == count(data.criteria)
	report.compliant == false
}
