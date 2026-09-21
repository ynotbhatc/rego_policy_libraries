package essential_eight.patch_applications_test

import rego.v1

import data.essential_eight.patch_applications

# Build an input that attests every requirement as true.
all_attested := {"essential_eight": {"patch_applications": {"requirements": all_true}}}

all_true := {id: true | some id, _ in patch_applications.requirements}

# Empty input: every requirement should fire and the strategy is not compliant.
test_empty_input_all_fire if {
	violations := patch_applications.violation with input as {}
	count(violations) == count(patch_applications.requirements)
	not patch_applications.strategy_compliant with input as {}
}

# Fully attested: no violations and the strategy is compliant.
test_all_attested_compliant if {
	violations := patch_applications.violation with input as all_attested
	count(violations) == 0
	patch_applications.strategy_compliant with input as all_attested
}

# Flip a single requirement off: exactly one violation, naming that id.
test_single_flip_one_violation if {
	flipped := {"essential_eight": {"patch_applications": {"requirements": object.remove(all_true, {"PA-ML1-3"})}}}
	violations := patch_applications.violation with input as flipped
	count(violations) == 1
	some msg in violations
	contains(msg, "PA-ML1-3")
}

# compliance_report is populated on empty input.
test_compliance_report_on_empty if {
	report := patch_applications.compliance_report with input as {}
	report.strategy == "Patch Applications"
	report.compliant == false
	report.requirements_evaluated == count(patch_applications.requirements)
	report.violation_count == count(patch_applications.requirements)
}
