package cjis.media_protection_test

import rego.v1

import data.cjis.media_protection

# Build an input that attests every requirement as true.
all_true := {"cjis": {"media_protection": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in media_protection.requirements}
}

# Empty input -> every requirement fires as a violation and the area is not compliant.
test_empty_input_all_fire if {
	count(media_protection.violation) == count(media_protection.requirements) with input as {}
	count(media_protection.violation) > 0 with input as {}
	not media_protection.area_compliant with input as {}
}

# Fully attested -> no violations and the area is compliant.
test_all_attested_compliant if {
	count(media_protection.violation) == 0 with input as all_true
	media_protection.area_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := object.union(all_true, {"cjis": {"media_protection": {"requirements": object.union(all_true.cjis.media_protection.requirements, {"MP-5": false})}}})
	count(media_protection.violation) == 1 with input as broken
	some msg in media_protection.violation with input as broken
	contains(msg, "MP-5") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := media_protection.compliance_report with input as {}
	report.policy_area == 8
	report.area_name == "Media Protection"
	report.requirements_evaluated == count(media_protection.requirements)
	report.violation_count == count(media_protection.requirements)
	report.compliant == false
}
