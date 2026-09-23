package bsi_c5.personnel_test

import rego.v1

import data.bsi_c5.personnel

# Build an input that attests every requirement as true.
all_true := {"bsi_c5": {"personnel": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in personnel.requirements}
}

# Empty input -> every requirement fires as a violation and the domain is not compliant.
test_empty_input_all_fire if {
	count(personnel.violation) == count(personnel.requirements) with input as {}
	count(personnel.violation) > 0 with input as {}
	not personnel.domain_compliant with input as {}
}

# Fully attested -> no violations and the domain is compliant.
test_all_attested_compliant if {
	count(personnel.violation) == 0 with input as all_true
	personnel.domain_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.bsi_c5.personnel.requirements, {"HR-2": false})
	broken := object.union(all_true, {"bsi_c5": {"personnel": {"requirements": flipped}}})
	count(personnel.violation) == 1 with input as broken
	some msg in personnel.violation with input as broken
	contains(msg, "HR-2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := personnel.compliance_report with input as {}
	report.domain == "HR"
	report.area_name == "Personnel"
	report.requirements_evaluated == count(personnel.requirements)
	report.violation_count == count(personnel.requirements)
	report.compliant == false
}
