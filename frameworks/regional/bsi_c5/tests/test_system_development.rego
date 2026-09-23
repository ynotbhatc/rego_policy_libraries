package bsi_c5.system_development_test

import rego.v1

import data.bsi_c5.system_development

# Build an input that attests every requirement as true.
all_true := {"bsi_c5": {"system_development": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in system_development.requirements}
}

# Empty input -> every requirement fires as a violation and the domain is not compliant.
test_empty_input_all_fire if {
	count(system_development.violation) == count(system_development.requirements) with input as {}
	count(system_development.violation) > 0 with input as {}
	not system_development.domain_compliant with input as {}
}

# Fully attested -> no violations and the domain is compliant.
test_all_attested_compliant if {
	count(system_development.violation) == 0 with input as all_true
	system_development.domain_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.bsi_c5.system_development.requirements, {"DEV-2": false})
	broken := object.union(all_true, {"bsi_c5": {"system_development": {"requirements": flipped}}})
	count(system_development.violation) == 1 with input as broken
	some msg in system_development.violation with input as broken
	contains(msg, "DEV-2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := system_development.compliance_report with input as {}
	report.domain == "DEV"
	report.area_name == "Procurement, Development and Modification of Information Systems"
	report.requirements_evaluated == count(system_development.requirements)
	report.violation_count == count(system_development.requirements)
	report.compliant == false
}
