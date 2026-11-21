package technical_debt.scoring_numeric_guards_test

import rego.v1

# A non-numeric age ("x", null) counts as 0 days, never as the >=90 tier ("x" sorts above every number).
test_text_age_scores_as_zero_days if {
	zero := data.technical_debt.scoring.debt_score with input as {"hostname": "h1", "framework": "nerc_cip", "violations": ["CIP-007: x"], "debt_age_days": 0}
	text := data.technical_debt.scoring.debt_score with input as {"hostname": "h1", "framework": "nerc_cip", "violations": ["CIP-007: x"], "debt_age_days": "x"}
	text == zero
}

test_null_age_scores_as_zero_days if {
	zero := data.technical_debt.scoring.debt_score with input as {"hostname": "h1", "framework": "nerc_cip", "violations": ["CIP-007: x"], "debt_age_days": 0}
	nul := data.technical_debt.scoring.debt_score with input as {"hostname": "h1", "framework": "nerc_cip", "violations": ["CIP-007: x"], "debt_age_days": null}
	nul == zero
}

test_string_age_is_converted if {
	one := data.technical_debt.scoring.debt_score with input as {"hostname": "h1", "framework": "nerc_cip", "violations": ["CIP-007: x"], "debt_age_days": 1}
	str := data.technical_debt.scoring.debt_score with input as {"hostname": "h1", "framework": "nerc_cip", "violations": ["CIP-007: x"], "debt_age_days": "1"}
	str == one
}

test_numeric_age_tier_unchanged if {
	zero := data.technical_debt.scoring.debt_score with input as {"hostname": "h1", "framework": "nerc_cip", "violations": ["CIP-007: x"], "debt_age_days": 0}
	old := data.technical_debt.scoring.debt_score with input as {"hostname": "h1", "framework": "nerc_cip", "violations": ["CIP-007: x"], "debt_age_days": 120}
	old == zero * 1.5
}
