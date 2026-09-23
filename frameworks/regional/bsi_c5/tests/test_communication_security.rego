package bsi_c5.communication_security_test

import rego.v1

import data.bsi_c5.communication_security

# Build an input that attests every requirement as true.
all_true := {"bsi_c5": {"communication_security": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in communication_security.requirements}
}

# Empty input -> every requirement fires as a violation and the domain is not compliant.
test_empty_input_all_fire if {
	count(communication_security.violation) == count(communication_security.requirements) with input as {}
	count(communication_security.violation) > 0 with input as {}
	not communication_security.domain_compliant with input as {}
}

# Fully attested -> no violations and the domain is compliant.
test_all_attested_compliant if {
	count(communication_security.violation) == 0 with input as all_true
	communication_security.domain_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.bsi_c5.communication_security.requirements, {"COS-2": false})
	broken := object.union(all_true, {"bsi_c5": {"communication_security": {"requirements": flipped}}})
	count(communication_security.violation) == 1 with input as broken
	some msg in communication_security.violation with input as broken
	contains(msg, "COS-2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := communication_security.compliance_report with input as {}
	report.domain == "COS"
	report.area_name == "Communication Security"
	report.requirements_evaluated == count(communication_security.requirements)
	report.violation_count == count(communication_security.requirements)
	report.compliant == false
}
