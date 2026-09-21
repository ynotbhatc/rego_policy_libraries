package cjis.security_awareness_training_test

import rego.v1

import data.cjis.security_awareness_training

all_attested := {"cjis": {"security_awareness_training": {"requirements": {
	"SAT-1": true,
	"SAT-2": true,
	"SAT-3": true,
	"SAT-4": true,
	"SAT-5": true,
	"SAT-6": true,
	"SAT-7": true,
}}}}

# Empty input: every requirement fires and the area is not compliant.
test_empty_input_all_violations if {
	count(security_awareness_training.violation) == count(security_awareness_training.requirements) with input as {}
	not security_awareness_training.area_compliant with input as {}
}

# All attested: no violations and the area is compliant.
test_all_attested_compliant if {
	count(security_awareness_training.violation) == 0 with input as all_attested
	security_awareness_training.area_compliant with input as all_attested
}

# Single flip: exactly one violation, naming its id.
test_single_flip_one_violation if {
	inp := json.remove(all_attested, ["cjis/security_awareness_training/requirements/SAT-2"])
	violations := security_awareness_training.violation with input as inp
	count(violations) == 1
	some msg in violations
	contains(msg, "SAT-2")
}

# compliance_report is populated on empty input.
test_compliance_report_populated if {
	report := security_awareness_training.compliance_report with input as {}
	report.policy_area == 2
	report.area_name == "Security Awareness Training"
	report.requirements_evaluated == count(security_awareness_training.requirements)
	report.violation_count == count(security_awareness_training.requirements)
	report.compliant == false
}
