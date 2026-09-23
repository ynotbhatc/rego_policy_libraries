package bsi_c5.incident_management_test

import rego.v1

import data.bsi_c5.incident_management

# Build an input that attests every requirement as true.
all_true := {"bsi_c5": {"incident_management": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in incident_management.requirements}
}

# Empty input -> every requirement fires as a violation and the domain is not compliant.
test_empty_input_all_fire if {
	count(incident_management.violation) == count(incident_management.requirements) with input as {}
	count(incident_management.violation) > 0 with input as {}
	not incident_management.domain_compliant with input as {}
}

# Fully attested -> no violations and the domain is compliant.
test_all_attested_compliant if {
	count(incident_management.violation) == 0 with input as all_true
	incident_management.domain_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.bsi_c5.incident_management.requirements, {"SIM-2": false})
	broken := object.union(all_true, {"bsi_c5": {"incident_management": {"requirements": flipped}}})
	count(incident_management.violation) == 1 with input as broken
	some msg in incident_management.violation with input as broken
	contains(msg, "SIM-2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := incident_management.compliance_report with input as {}
	report.domain == "SIM"
	report.area_name == "Security Incident Management"
	report.requirements_evaluated == count(incident_management.requirements)
	report.violation_count == count(incident_management.requirements)
	report.compliant == false
}
