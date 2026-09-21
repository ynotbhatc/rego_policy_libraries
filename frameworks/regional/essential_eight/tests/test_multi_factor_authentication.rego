package essential_eight.multi_factor_authentication_test

import rego.v1

import data.essential_eight.multi_factor_authentication as mfa

# All-true requirements attestation derived from the module itself.
all_attested := {"essential_eight": {"multi_factor_authentication": {"requirements": {id: true |
	some id, _ in mfa.requirements
}}}}

# Empty input: every requirement fires as a violation and the strategy is non-compliant.
test_empty_input_all_violations_fire if {
	count(mfa.violation) == count(mfa.requirements)
	not mfa.strategy_compliant
}

# Fully attested: no violations and the strategy is compliant.
test_all_attested_no_violations if {
	count(mfa.violation) == 0 with input as all_attested
	mfa.strategy_compliant with input as all_attested
}

# Single flip: one requirement un-attested yields exactly one violation naming its id.
test_single_flip_one_named_violation if {
	flipped := "MFA-ML2-2"
	reqs := object.union({id: true | some id, _ in mfa.requirements}, {flipped: false})
	inp := {"essential_eight": {"multi_factor_authentication": {"requirements": reqs}}}

	vs := mfa.violation with input as inp
	count(vs) == 1
	some msg in vs
	contains(msg, flipped)
	not mfa.strategy_compliant with input as inp
}

# Report is populated even on empty input (no field collapses to {}).
test_report_populated_on_empty_input if {
	r := mfa.compliance_report
	r.strategy == "Multi-Factor Authentication"
	r.requirements_evaluated == count(mfa.requirements)
	r.violation_count == count(mfa.requirements)
	r.compliant == false
}
