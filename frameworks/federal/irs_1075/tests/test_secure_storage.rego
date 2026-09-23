package irs_1075.secure_storage_test

import rego.v1

import data.irs_1075.secure_storage

# Build an input that attests every requirement as true.
all_true := {"irs_1075": {"secure_storage": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in secure_storage.requirements}
}

# Empty input -> every requirement fires as a violation and the area is not compliant.
test_empty_input_all_fire if {
	count(secure_storage.violation) == count(secure_storage.requirements) with input as {}
	count(secure_storage.violation) > 0 with input as {}
	not secure_storage.area_compliant with input as {}
}

# Fully attested -> no violations and the area is compliant.
test_all_attested_compliant if {
	count(secure_storage.violation) == 0 with input as all_true
	secure_storage.area_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := object.union(all_true, {"irs_1075": {"secure_storage": {"requirements": object.union(all_true.irs_1075.secure_storage.requirements, {"SS-5": false})}}})
	count(secure_storage.violation) == 1 with input as broken
	some msg in secure_storage.violation with input as broken
	contains(msg, "SS-5") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := secure_storage.compliance_report with input as {}
	report.section == "4"
	report.area_name == "Secure Storage"
	report.requirements_evaluated == count(secure_storage.requirements)
	report.violation_count == count(secure_storage.requirements)
	report.compliant == false
}
