package bsi_c5.business_continuity_test

import rego.v1

import data.bsi_c5.business_continuity

# Build an input that attests every requirement as true.
all_true := {"bsi_c5": {"business_continuity": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in business_continuity.requirements}
}

# Empty input -> every requirement fires as a violation and the domain is not compliant.
test_empty_input_all_fire if {
	count(business_continuity.violation) == count(business_continuity.requirements) with input as {}
	count(business_continuity.violation) > 0 with input as {}
	not business_continuity.domain_compliant with input as {}
}

# Fully attested -> no violations and the domain is compliant.
test_all_attested_compliant if {
	count(business_continuity.violation) == 0 with input as all_true
	business_continuity.domain_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.bsi_c5.business_continuity.requirements, {"BCM-2": false})
	broken := object.union(all_true, {"bsi_c5": {"business_continuity": {"requirements": flipped}}})
	count(business_continuity.violation) == 1 with input as broken
	some msg in business_continuity.violation with input as broken
	contains(msg, "BCM-2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := business_continuity.compliance_report with input as {}
	report.domain == "BCM"
	report.area_name == "Business Continuity Management"
	report.requirements_evaluated == count(business_continuity.requirements)
	report.violation_count == count(business_continuity.requirements)
	report.compliant == false
}
