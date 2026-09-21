package essential_eight.user_application_hardening_test

import rego.v1

import data.essential_eight.user_application_hardening

# Empty input → every requirement fires as a violation and strategy is not compliant.
test_empty_input_all_violations if {
	count(user_application_hardening.violation) == count(user_application_hardening.requirements) with input as {}
	not user_application_hardening.strategy_compliant with input as {}
}

# All requirements attested → no violations and strategy is compliant.
test_all_attested_compliant if {
	attested := {"essential_eight": {"user_application_hardening": {"requirements": all_true}}}
	count(user_application_hardening.violation) == 0 with input as attested
	user_application_hardening.strategy_compliant with input as attested
}

# Flipping a single requirement to false yields exactly one violation naming its id.
test_single_flip_one_violation if {
	partial := {"essential_eight": {"user_application_hardening": {"requirements": object.union(all_true, {"UAH-ML1-1": false})}}}
	count(user_application_hardening.violation) == 1 with input as partial
	not user_application_hardening.strategy_compliant with input as partial
	some msg in user_application_hardening.violation with input as partial
	contains(msg, "UAH-ML1-1") with input as partial
}

# The compliance report is populated even on empty input.
test_report_populated_on_empty if {
	report := user_application_hardening.compliance_report with input as {}
	report.strategy == "User Application Hardening"
	report.requirements_evaluated == count(user_application_hardening.requirements)
	report.violation_count == count(user_application_hardening.requirements)
	report.compliant == false
}

# Helper: every requirement id set to true.
all_true := {id: true | some id, _ in user_application_hardening.requirements}
