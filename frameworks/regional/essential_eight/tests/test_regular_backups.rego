package essential_eight.regular_backups_test

import rego.v1

import data.essential_eight.regular_backups as rb

# All-true requirements attestation derived from the module itself.
all_attested := {"essential_eight": {"regular_backups": {"requirements": {id: true |
	some id, _ in rb.requirements
}}}}

# Empty input: every requirement fires as a violation and the strategy is non-compliant.
test_empty_input_all_violations_fire if {
	count(rb.violation) == count(rb.requirements)
	not rb.strategy_compliant
}

# Fully attested: no violations and the strategy is compliant.
test_all_attested_no_violations if {
	count(rb.violation) == 0 with input as all_attested
	rb.strategy_compliant with input as all_attested
}

# Single flip: one requirement un-attested yields exactly one violation naming its id.
test_single_flip_one_named_violation if {
	flipped := "RB-ML3-1"
	reqs := object.union({id: true | some id, _ in rb.requirements}, {flipped: false})
	inp := {"essential_eight": {"regular_backups": {"requirements": reqs}}}

	vs := rb.violation with input as inp
	count(vs) == 1
	some msg in vs
	contains(msg, flipped)
	not rb.strategy_compliant with input as inp
}

# Report is populated even on empty input (no field collapses to {}).
test_report_populated_on_empty_input if {
	r := rb.compliance_report
	r.strategy == "Regular Backups"
	r.requirements_evaluated == count(rb.requirements)
	r.violation_count == count(rb.requirements)
	r.compliant == false
}
