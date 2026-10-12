# Tests for apra_cps234.main — APRA CPS 234 Information Security.
package apra_cps234.main_test

import rego.v1

import data.apra_cps234.main

_all := {id: true | some id, _ in main.controls}

_no_tp := {id: true | some id, c in main.controls; not c.tp}

test_table_has_24_paragraphs_13_to_36 if {
	count(main.controls) == 24
	{id | some id, _ in main.controls} == {sprintf("%d", [n]) | some n in numbers.range(13, 36)}
}

test_four_third_party_paragraphs if {
	{id | some id, c in main.controls; c.tp} == {"16", "22", "28", "34"}
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.third_party_managed_assets == "undeclared"

	# 1 flag + 20 non-third-party paragraphs
	r.violation_count == 21
}

test_entity_without_third_parties_is_compliant_with_20 if {
	inp := {"apra_cps234": {"third_party_managed_assets": false, "controls": _no_tp}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.controls_evaluated == 20
}

test_entity_with_third_parties_needs_all_24 if {
	inp := {"apra_cps234": {"third_party_managed_assets": true, "controls": _no_tp}}
	r := main.compliance_report with input as inp
	r.violation_count == 4
	r.sections.capability.gaps == ["16"]
	main.compliant with input as {"apra_cps234": {"third_party_managed_assets": true, "controls": _all}}
}

test_string_true_is_not_an_attestation if {
	inp := {"apra_cps234": {"third_party_managed_assets": true, "controls": object.union(_all, {"35": "true"})}}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "72 hours")
}

test_unknown_paragraph_flagged if {
	inp := {"apra_cps234": {"third_party_managed_assets": true, "controls": object.union(_all, {"37": true})}}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "unknown paragraph 37")
}

test_section_report_lists_gaps if {
	inp := {"apra_cps234": {"third_party_managed_assets": false, "controls": object.remove(_no_tp, {"35", "36"})}}
	r := main.compliance_report with input as inp
	r.sections.notification.gaps == ["35", "36"]
	r.violation_count == 2
}
