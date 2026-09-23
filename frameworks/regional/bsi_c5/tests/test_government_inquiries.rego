package bsi_c5.government_inquiries_test

import rego.v1

import data.bsi_c5.government_inquiries

# Build an input that attests every requirement as true.
all_true := {"bsi_c5": {"government_inquiries": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in government_inquiries.requirements}
}

# Empty input -> every requirement fires as a violation and the domain is not compliant.
test_empty_input_all_fire if {
	count(government_inquiries.violation) == count(government_inquiries.requirements) with input as {}
	count(government_inquiries.violation) > 0 with input as {}
	not government_inquiries.domain_compliant with input as {}
}

# Fully attested -> no violations and the domain is compliant.
test_all_attested_compliant if {
	count(government_inquiries.violation) == 0 with input as all_true
	government_inquiries.domain_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.bsi_c5.government_inquiries.requirements, {"INQ-2": false})
	broken := object.union(all_true, {"bsi_c5": {"government_inquiries": {"requirements": flipped}}})
	count(government_inquiries.violation) == 1 with input as broken
	some msg in government_inquiries.violation with input as broken
	contains(msg, "INQ-2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := government_inquiries.compliance_report with input as {}
	report.domain == "INQ"
	report.area_name == "Dealing with Investigation Requests from Government Agencies"
	report.requirements_evaluated == count(government_inquiries.requirements)
	report.violation_count == count(government_inquiries.requirements)
	report.compliant == false
}
