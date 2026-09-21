package essential_eight.application_control_test

import rego.v1

import data.essential_eight.application_control

# Build an input that attests every requirement as true.
all_attested := {"essential_eight": {"application_control": {"requirements": all_true}}}

all_true := {id: true | some id, _ in application_control.requirements}

# Empty input: every requirement should fire and the strategy is not compliant.
test_empty_input_all_fire if {
	violations := application_control.violation with input as {}
	count(violations) == count(application_control.requirements)
	not application_control.strategy_compliant with input as {}
}

# Fully attested: no violations and the strategy is compliant.
test_all_attested_compliant if {
	violations := application_control.violation with input as all_attested
	count(violations) == 0
	application_control.strategy_compliant with input as all_attested
}

# Flip a single requirement off: exactly one violation, naming that id.
test_single_flip_one_violation if {
	flipped := {"essential_eight": {"application_control": {"requirements": object.remove(all_true, {"AC-ML2-3"})}}}
	violations := application_control.violation with input as flipped
	count(violations) == 1
	some msg in violations
	contains(msg, "AC-ML2-3")
}

# compliance_report is populated on empty input.
test_compliance_report_on_empty if {
	report := application_control.compliance_report with input as {}
	report.strategy == "Application Control"
	report.compliant == false
	report.requirements_evaluated == count(application_control.requirements)
	report.violation_count == count(application_control.requirements)
}
