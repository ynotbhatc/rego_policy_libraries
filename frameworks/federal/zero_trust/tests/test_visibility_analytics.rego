package zero_trust.visibility_analytics_test

import rego.v1

import data.zero_trust.visibility_analytics

# Build an input that attests every criterion as true.
all_true := {"zero_trust": {"visibility_analytics": {"criteria": {id: true |
	some id, _ in visibility_analytics.criteria
}}}}

# Empty attestation → every criterion fires a violation and capability is not compliant.
test_empty_input_all_fire if {
	inp := {"zero_trust": {"visibility_analytics": {"criteria": {}}}}
	count(visibility_analytics.violation) == count(visibility_analytics.criteria) with input as inp
	not visibility_analytics.pillar_compliant with input as inp
}

# Fully attested → no violations and capability is compliant.
test_all_attested_compliant if {
	count(visibility_analytics.violation) == 0 with input as all_true
	visibility_analytics.pillar_compliant with input as all_true
}

# Flipping a single criterion to false yields exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true, {"zero_trust": {"visibility_analytics": {"criteria": {"VIS-3": false}}}})
	count(visibility_analytics.violation) == 1 with input as flipped
	not visibility_analytics.pillar_compliant with input as flipped
	some msg in visibility_analytics.violation with input as flipped
	contains(msg, "VIS-3") with input as flipped
}

# Report is populated on empty input.
test_report_populated_on_empty if {
	inp := {"zero_trust": {"visibility_analytics": {"criteria": {}}}}
	report := visibility_analytics.compliance_report with input as inp
	report.pillar == "Visibility & Analytics"
	report.criteria_evaluated == count(visibility_analytics.criteria)
	report.violation_count == count(visibility_analytics.criteria)
	report.compliant == false
}
