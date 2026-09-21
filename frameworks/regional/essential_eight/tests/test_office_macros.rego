package essential_eight.office_macros_test

import rego.v1

import data.essential_eight.office_macros

# Empty input → every requirement fires as a violation and strategy is not compliant.
test_empty_input_all_violations if {
	count(office_macros.violation) == count(office_macros.requirements) with input as {}
	not office_macros.strategy_compliant with input as {}
}

# All requirements attested → no violations and strategy is compliant.
test_all_attested_compliant if {
	attested := {"essential_eight": {"office_macros": {"requirements": all_true}}}
	count(office_macros.violation) == 0 with input as attested
	office_macros.strategy_compliant with input as attested
}

# Flipping a single requirement to false yields exactly one violation naming its id.
test_single_flip_one_violation if {
	partial := {"essential_eight": {"office_macros": {"requirements": object.union(all_true, {"OM-ML2-1": false})}}}
	count(office_macros.violation) == 1 with input as partial
	not office_macros.strategy_compliant with input as partial
	some msg in office_macros.violation with input as partial
	contains(msg, "OM-ML2-1") with input as partial
}

# The compliance report is populated even on empty input.
test_report_populated_on_empty if {
	report := office_macros.compliance_report with input as {}
	report.strategy == "Configure Microsoft Office Macro Settings"
	report.requirements_evaluated == count(office_macros.requirements)
	report.violation_count == count(office_macros.requirements)
	report.compliant == false
}

# Helper: every requirement id set to true.
all_true := {id: true | some id, _ in office_macros.requirements}
