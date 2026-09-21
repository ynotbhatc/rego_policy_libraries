package cjis.incident_response_test

import rego.v1

import data.cjis.incident_response

all_attested := {"cjis": {"incident_response": {"requirements": {
	"IR-1": true,
	"IR-2": true,
	"IR-3": true,
	"IR-4": true,
	"IR-5": true,
	"IR-6": true,
	"IR-7": true,
	"IR-8": true,
}}}}

# Empty input: every requirement fires and the area is not compliant.
test_empty_input_all_violations if {
	count(incident_response.violation) == count(incident_response.requirements) with input as {}
	not incident_response.area_compliant with input as {}
}

# All attested: no violations and the area is compliant.
test_all_attested_compliant if {
	count(incident_response.violation) == 0 with input as all_attested
	incident_response.area_compliant with input as all_attested
}

# Single flip: exactly one violation, naming its id.
test_single_flip_one_violation if {
	inp := json.remove(all_attested, ["cjis/incident_response/requirements/IR-4"])
	violations := incident_response.violation with input as inp
	count(violations) == 1
	some msg in violations
	contains(msg, "IR-4")
}

# compliance_report is populated on empty input.
test_compliance_report_populated if {
	report := incident_response.compliance_report with input as {}
	report.policy_area == 3
	report.area_name == "Incident Response"
	report.requirements_evaluated == count(incident_response.requirements)
	report.violation_count == count(incident_response.requirements)
	report.compliant == false
}
