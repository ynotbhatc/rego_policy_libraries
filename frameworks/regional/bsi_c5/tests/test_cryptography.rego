package bsi_c5.cryptography_test

import rego.v1

import data.bsi_c5.cryptography

# Build an input that attests every requirement as true.
all_true := {"bsi_c5": {"cryptography": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in cryptography.requirements}
}

# Empty input -> every requirement fires as a violation and the domain is not compliant.
test_empty_input_all_fire if {
	count(cryptography.violation) == count(cryptography.requirements) with input as {}
	count(cryptography.violation) > 0 with input as {}
	not cryptography.domain_compliant with input as {}
}

# Fully attested -> no violations and the domain is compliant.
test_all_attested_compliant if {
	count(cryptography.violation) == 0 with input as all_true
	cryptography.domain_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.bsi_c5.cryptography.requirements, {"CRY-2": false})
	broken := object.union(all_true, {"bsi_c5": {"cryptography": {"requirements": flipped}}})
	count(cryptography.violation) == 1 with input as broken
	some msg in cryptography.violation with input as broken
	contains(msg, "CRY-2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := cryptography.compliance_report with input as {}
	report.domain == "CRY"
	report.area_name == "Cryptography and Key Management"
	report.requirements_evaluated == count(cryptography.requirements)
	report.violation_count == count(cryptography.requirements)
	report.compliant == false
}
