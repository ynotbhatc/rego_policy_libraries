# Tests for cms_mars_e.main — CMS MARS-E 2.0 Volume III catalog (superseded by ARC-AMPE).
package cms_mars_e.main_test

import rego.v1

import data.cms_mars_e.main

_all := {r.id: true | some r in main.control_rows}

test_row_counts_pinned if {
	count(main.control_rows) == 352
	count(main.control_by_id) == 352
	count(main.families) == 26
	count({r.id | some r in main.control_rows; main.family_parts[r.family] == "security"}) == 316
	count({r.id | some r in main.control_rows; main.family_parts[r.family] == "privacy"}) == 36
	count({r.id | some r in main.control_rows; r.family == "AC"}) == 38
	count({r.id | some r in main.control_rows; r.family == "SC"}) == 34
	count({r.id | some r in main.control_rows; r.kind == "enhancement"}) == count({r.id | some r in main.control_rows; contains(r.id, "(")})
}

test_every_row_has_a_known_family_and_matching_prefix if {
	count({r.id | some r in main.control_rows; not main.families[r.family]}) == 0
	count({r.id | some r in main.control_rows; not startswith(r.id, concat("", [r.family, "-"]))}) == 0
}

test_baseline_flags_are_closed_values if {
	vals := {"selected", "not_selected", "n/a"}
	count({r.id | some r in main.control_rows; not r.nist_800_53r4_moderate in vals}) == 0
	main.control_by_id["AC-2 (7)"].nist_800_53r4_moderate == "not_selected"
	main.control_by_id["AC-2 (7)"].cms_ars_2_0 == "selected"
	main.control_by_id["UL-2"].nist_800_53r4_moderate == "n/a"
	main.control_by_id["MA-4 (1)"].nist_800_53r4_moderate == "not_selected"
	main.control_by_id["MA-4 (1)"].cms_ars_2_0 == "selected"
	main.control_by_id["SA-9 (1)"].nist_800_53r4_moderate == "not_selected"
	main.control_by_id["PE-13 (1)"].nist_800_53r4_moderate == "not_selected"
	main.control_by_id["PE-13 (3)"].nist_800_53r4_moderate == "selected"
}

test_cms_specific_controls_present if {
	main.control_by_id["SC-ACA-1"].title == "Electronic Mail"
	main.control_by_id["SC-ACA-2"].title == "FAX Usage"
	main.control_by_id["MP-CMS-1"]
	main.control_by_id["DI-1 (1)"].title == "Validate PII"
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some m in r.violations
	contains(m, "FAIL-CLOSED")

	# FAIL-CLOSED notice + 352 unattested rows
	r.violation_count == 353
}

test_non_object_container_fails_closed if {
	v := main.violations with input as {"cms_mars_e": {"controls": ["AC-1"]}}
	some m in v
	contains(m, "FAIL-CLOSED")
}

test_full_attestation_is_compliant if {
	main.compliant with input as {"cms_mars_e": {"controls": _all}}
	r := main.compliance_report with input as {"cms_mars_e": {"controls": _all}}
	r.controls_attested == 352
	r.families.AC.not_attested == []
}

test_one_false_is_named if {
	inp := {"cms_mars_e": {"controls": object.union(_all, {"AC-2 (1)": false})}}
	v := main.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "CMS MARS-E AC-2 (1) (AC Access Control)")
	r := main.compliance_report with input as inp
	r.families.AC.not_attested == ["AC-2 (1)"]
}

test_string_true_rejected_and_unknown_id_flagged if {
	inp := {"cms_mars_e": {"controls": object.union(_all, {"SC-28": "true", "AC-2(1)": true})}}
	v := main.violations with input as inp
	count(v) == 2
	some m1 in v
	contains(m1, "CMS MARS-E SC-28 ")
	some m2 in v
	contains(m2, "unknown control id AC-2(1)")
}

test_report_records_status if {
	r := main.compliance_report with input as {}
	r.source.status == "superseded"
	r.standard_total == 352
}
