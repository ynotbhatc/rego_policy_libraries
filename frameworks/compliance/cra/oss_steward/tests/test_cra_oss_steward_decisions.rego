package cra.oss_steward_test

import rego.v1

# decisions 2026-10-19: undeclared Art. 3(14) threshold facts are "applicability not determined".

m := data.cra.oss_steward

test_steward_empty_input_is_not_compliant if {
	not m.compliant with input as {}
	count([x | some x in m.violation with input as {}; contains(x, "applicability not determined")]) == 1
}

test_steward_one_declared_false_element_is_not_a_steward if {
	m.compliant with input as {"oss_steward": {"is_legal_person": false}}
}

test_steward_partially_declared_true_elements_are_undetermined if {
	i := {"oss_steward": {"is_legal_person": true, "not_manufacturer_of_product": true}}
	not m.compliant with input as i
	some x in m.violation with input as i
	contains(x, "ensures_product_viability")
}

test_steward_all_declared_and_met_still_requires_art24_policy if {
	i := {"oss_steward": {
		"is_legal_person": true, "not_manufacturer_of_product": true, "provides_systematic_sustained_support": true,
		"ensures_product_viability": true, "oss_product_intended_for_commercial_activities": true,
	}}
	not m.compliant with input as i
	count([x | some x in m.violation with input as i; contains(x, "applicability not determined")]) == 0
}
