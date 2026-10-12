# Tests for meti_csm.main — METI Cybersecurity Management Guidelines Ver. 3.0, Appendix A.
package meti_csm.main_test

import rego.v1

import data.meti_csm.main

_all := {id: true | some id, _ in main.items}

test_table_has_49_items if {
	count(main.items) == 49
}

test_nine_principle_items_and_forty_direction_items if {
	count({id | some id, it in main.items; startswith(it.g, "P")}) == 9
	count({id | some id, it in main.items; startswith(it.g, "D")}) == 40
}

test_every_item_has_a_known_group_and_matching_prefix if {
	count({id | some id, it in main.items; not main.groups[it.g]}) == 0
	count({id | some id, it in main.items; not startswith(id, concat("", [it.g, "-"]))}) == 0
}

test_direction_5_has_ten_items if {
	count({id | some id, it in main.items; it.g == "D5"}) == 10
}

test_empty_input_is_all_violations if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 49
	r.items_attested == 0
}

test_full_attestation_is_compliant if {
	main.compliant with input as {"meti_csm": {"items": _all}}
}

test_string_true_is_not_an_attestation if {
	inp := {"meti_csm": {"items": object.union(_all, {"D5-06": "true"})}}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "D5-06")
}

test_unknown_id_is_flagged if {
	inp := {"meti_csm": {"items": object.union(_all, {"D11-01": true})}}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "unknown item id D11-01")
}

test_non_object_items_flagged if {
	v := main.violations with input as {"meti_csm": {"items": ["D1-01"]}}
	some msg in v
	contains(msg, "must be an object")
}

test_group_report_lists_gaps if {
	inp := {"meti_csm": {"items": object.remove(_all, {"D7-02", "D7-04"})}}
	r := main.compliance_report with input as inp
	r.groups.D7.items == 5
	r.groups.D7.attested == 3
	r.groups.D7.gaps == ["D7-02", "D7-04"]
	r.violation_count == 2
}
