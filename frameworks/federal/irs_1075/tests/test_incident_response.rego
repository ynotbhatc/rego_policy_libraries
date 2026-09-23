package irs_1075.incident_response_test

import rego.v1

import data.irs_1075.incident_response

# Build an input that attests every requirement as true.
all_true := {"irs_1075": {"incident_response": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in incident_response.requirements}
}

# Empty input -> every requirement fires as a violation and the area is not compliant.
test_empty_input_all_fire if {
	count(incident_response.violation) == count(incident_response.requirements) with input as {}
	count(incident_response.violation) > 0 with input as {}
	not incident_response.area_compliant with input as {}
}

# Fully attested -> no violations and the area is compliant.
test_all_attested_compliant if {
	count(incident_response.violation) == 0 with input as all_true
	incident_response.area_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := object.union(all_true, {"irs_1075": {"incident_response": {"requirements": object.union(all_true.irs_1075.incident_response.requirements, {"IR-2": false})}}})
	count(incident_response.violation) == 1 with input as broken
	some msg in incident_response.violation with input as broken
	contains(msg, "IR-2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := incident_response.compliance_report with input as {}
	report.section == "10"
	report.area_name == "Incident Response"
	report.requirements_evaluated == count(incident_response.requirements)
	report.violation_count == count(incident_response.requirements)
	report.compliant == false
}
