package technical_debt.scoring_test

import rego.v1

# Generated smoke test for frameworks/management/technical_debt/debt_scoring.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_debt_scoring_loads_on_empty_input if {
	m := data.technical_debt.scoring with input as {}
	is_object(m)
}
