# Tests for aca_155_260.main — 45 CFR 155.260 privacy and security of PII.
package aca_155_260.main_test

import rego.v1

import data.aca_155_260.main

_all := {id: true | some id, _ in main.obligations}

_nee := {id: true | some id, r in main.obligations; "non_exchange_entity" in r.applies_to}

test_row_counts_pinned if {
	count(main.obligations_list) == 35
	count(main.obligations) == 35
	count({id | some id, r in main.obligations; r.section == "(a)"}) == 19
	count({id | some id, r in main.obligations; r.section == "(b)"}) == 8
	count({id | some id, r in main.obligations; startswith(id, "155.260(a)(3)(")}) == 8
	count(_nee) == 5
	main.compliance_report.standard_total == 35 with input as {}
}

test_every_row_has_known_section_and_role if {
	count({id | some id, r in main.obligations; not main.sections[r.section]}) == 0
	count({id | some id, r in main.obligations; some x in r.applies_to; not x in main.roles}) == 0
	count({id | some id, r in main.obligations; not startswith(id, concat("", ["155.260", r.section]))}) == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.role == "undeclared"
	some m in r.violations
	contains(m, "FAIL-CLOSED")

	# FAIL-CLOSED + undeclared role; no row is evaluated without a role
	r.violation_count == 2
}

test_exchange_all_true_is_compliant if {
	inp := {"aca_155_260": {"exchange_or_non_exchange_entity": "exchange", "obligations": _all}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.rows_evaluated == 35
	r.paragraphs["(a)"].rows_attested == 19
}

test_non_exchange_entity_needs_five if {
	inp := {"aca_155_260": {"exchange_or_non_exchange_entity": "non_exchange_entity", "obligations": _nee}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.rows_evaluated == 5
	r.paragraphs["(a)"].rows_evaluated == 0
}

test_non_exchange_entity_empty_lists_gaps if {
	r := main.compliance_report with input as {"aca_155_260": {"exchange_or_non_exchange_entity": "non_exchange_entity", "obligations": {}}}
	r.paragraphs["(b)"].gaps == ["155.260(b)(2)(ii)", "155.260(b)(2)(iii)", "155.260(b)(2)(iv)", "155.260(b)(2)(v)"]
	r.paragraphs["(f)"].gaps == ["155.260(f)"]
	r.violation_count == 5
}

test_one_false_is_named if {
	inp := {"aca_155_260": {"exchange_or_non_exchange_entity": "exchange", "obligations": object.union(_all, {"155.260(a)(5)": false})}}
	v := main.violations with input as inp
	count(v) == 1
	some m in v
	contains(m, "45 CFR 155.260(a)(5)")
}

test_invalid_role_and_unknown_id if {
	inp := {"aca_155_260": {"exchange_or_non_exchange_entity": "broker", "obligations": object.union(_all, {"155.260(g)": true})}}
	v := main.violations with input as inp
	count(v) == 2
	some m1 in v
	contains(m1, "must be declared")
	some m2 in v
	contains(m2, "unknown id 155.260(g)")
}

test_non_object_container_fails_closed if {
	v := main.violations with input as {"aca_155_260": {"exchange_or_non_exchange_entity": "exchange", "obligations": "all"}}
	some m in v
	contains(m, "FAIL-CLOSED")
}
