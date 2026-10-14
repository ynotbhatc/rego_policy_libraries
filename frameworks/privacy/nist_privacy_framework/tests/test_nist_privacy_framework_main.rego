# Tests for nist_privacy_framework.main — NIST Privacy Framework 1.0 Core subcategories (CPRT ids, sha256 c20d7fade235a6e2a23abdfab48e091b150ccf82804e89dbb4d1812e0bc96f20).
package nist_privacy_framework.main_test

import rego.v1

import data.nist_privacy_framework.main

_all := {id: true | some id, _ in main.subcategories}

_green := {"nist_privacy_framework": {"subcategories": _all}}

test_table_counts_match_cprt if {
	count(main.subcategories) == 100
	count(main.categories) == 18
	count(main.functions) == 5
	count(main.csf_relationships) == 3
	count({id | some id, s in main.subcategories; s.function == "ID-P"}) == 21
	count({id | some id, s in main.subcategories; s.function == "GV-P"}) == 20
	count({id | some id, s in main.subcategories; s.function == "CT-P"}) == 19
	count({id | some id, s in main.subcategories; s.function == "CM-P"}) == 10
	count({id | some id, s in main.subcategories; s.function == "PR-P"}) == 30
}

test_parentage_matches_id_spelling if {
	count({c | some c, cat in main.categories; not main.functions[cat.function]}) == 0
	count({c | some c, cat in main.categories; not startswith(c, concat("", [substring(cat.function, 0, 2), "."]))}) == 0
	count({id | some id, s in main.subcategories; not main.categories[s.category]}) == 0
	count({id | some id, s in main.subcategories; main.categories[s.category].function != s.function}) == 0
	count({id | some id, s in main.subcategories; not startswith(id, s.category)}) == 0
}

test_every_category_has_subcategories if {
	count({c | some c, _ in main.categories; count(main._by_category[c]) == 0}) == 0
}

test_csf_relationship_tags_carried_as_data if {
	count({id | some id, s in main.subcategories; not main.csf_relationships[s.csf_relationship]}) == 0
	r := main.compliance_report with input as {}
	r.csf_relationship_counts == {"csfr_none": 47, "csfr_adapted": 26, "csfr_identical": 27}
	main.functions["PR-P"].csf_relationship == "csfr_adapted"
	count({id | some id, s in main.subcategories; s.function == "PR-P"; s.csf_relationship == "csfr_identical"}) == 22
	count({id | some id, s in main.subcategories; s.function == "PR-P"; s.csf_relationship == "csfr_adapted"}) == 8
	main.csf_relationships.csfr_identical.text == "The Category or Subcategory is identical to the Cybersecurity Framework."
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
	r.categories_achieved == 0
	r.subcategories_achieved == 0
	r.violation_count == 101
}

test_non_object_subcategories_fail_closed if {
	r := main.compliance_report with input as {"nist_privacy_framework": {"subcategories": true}}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
}

test_full_green_input_is_compliant if {
	r := main.compliance_report with input as _green
	r.compliant == true
	r.violation_count == 0
	r.subcategories_achieved == 100
	r.categories_achieved == 18
	r.total_controls == 100
	r.standard_total == 100
}

test_one_subcategory_per_function_resolves if {
	r := main.compliance_report with input as _green
	main.subcategories["ID.IM-P1"].category == "ID.IM-P"
	main.subcategories["ID.IM-P1"].text == "Systems/products/services that process data are inventoried."
	r.functions["ID-P"].categories_achieved == 4
	main.subcategories["GV.PO-P1"].category == "GV.PO-P"
	main.subcategories["GV.PO-P1"].text == "Organizational privacy values and policies (e.g., conditions on data processing such as data uses or retention periods, individuals’ prerogatives with respect to data processing) are established and communicated."
	r.functions["GV-P"].categories_achieved == 4
	main.subcategories["CT.PO-P1"].category == "CT.PO-P"
	main.subcategories["CT.PO-P1"].text == "Policies, processes, and procedures for authorizing data processing (e.g., organizational decisions, individual consent), revoking authorizations, and maintaining authorizations are established and in place."
	r.functions["CT-P"].categories_achieved == 3
	main.subcategories["CM.PO-P1"].category == "CM.PO-P"
	main.subcategories["CM.PO-P1"].text == "Transparency policies, processes, and procedures for communicating data processing purposes, practices, and associated privacy risks are established and in place."
	r.functions["CM-P"].categories_achieved == 2
	main.subcategories["PR.PO-P1"].category == "PR.PO-P"
	main.subcategories["PR.PO-P1"].text == "A baseline configuration of information technology is created and maintained incorporating security principles (e.g., concept of least functionality)."
	r.functions["PR-P"].categories_achieved == 5
}

test_one_subcategory_false_is_named if {
	inp := json.patch(_green, [{"op": "replace", "path": "/nist_privacy_framework/subcategories/PR.DS-P2", "value": false}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	r.categories["PR.DS-P"].achieved == false
	r.categories["PR.DS-P"].not_achieved == ["PR.DS-P2"]
	r.functions["PR-P"].categories_not_achieved == ["PR.DS-P"]
	r.functions["PR-P"].subcategories_achieved == 29
	r.categories_achieved == 17
	some v in r.violations
	contains(v, "PR.DS-P2")
	contains(v, "Data-in-transit are protected.")
}

test_non_true_value_is_not_achieved if {
	inp := json.patch(_green, [{"op": "replace", "path": "/nist_privacy_framework/subcategories/PR.DS-P2", "value": "yes"}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.categories["PR.DS-P"].achieved == false
}

test_missing_subcategory_is_not_achieved if {
	inp := json.patch(_green, [{"op": "remove", "path": "/nist_privacy_framework/subcategories/ID.IM-P1"}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.categories["ID.IM-P"].not_achieved == ["ID.IM-P1"]
}

test_unknown_subcategory_id_is_rejected if {
	inp := json.patch(_green, [{"op": "add", "path": "/nist_privacy_framework/subcategories/PR.AC-1", "value": true}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	some v in r.violations
	contains(v, "unknown subcategory id PR.AC-1")
}
