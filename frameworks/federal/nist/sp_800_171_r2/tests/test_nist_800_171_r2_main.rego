# Tests for nist.sp800_171_r2.main — NIST SP 800-171 Rev 2 (110 requirements).
package nist.sp800_171_r2.main_test

import rego.v1

import data.nist.sp800_171_r2.main

_all := {id: true | some id, _ in main.requirements}

test_table_matches_cprt_export_counts if {
	count(main.requirements) == 110
	count(main.families) == 14
	count({id | some id, r in main.requirements; r.type == "basic"}) == 31
	count({id | some id, r in main.requirements; r.type == "derived"}) == 79
	count({id | some id, r in main.requirements; r.family == "3.1"}) == 22
	count({id | some id, r in main.requirements; r.family == "3.13"}) == 16
}

test_every_requirement_has_known_family_matching_prefix_and_text if {
	count({id | some id, r in main.requirements; not main.families[r.family]}) == 0
	count({id | some id, r in main.requirements; not startswith(id, concat("", [r.family, "."]))}) == 0
	count({id | some id, r in main.requirements; r.text == ""}) == 0
}

test_first_requirement_text_is_verbatim if {
	main.requirements["3.1.1"].text == "Limit system access to authorized users, processes acting on behalf of authorized users, and devices (including other systems)."
	main.requirements["3.1.1"].type == "basic"
}

test_empty_input_fails_closed_with_explicit_violation if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some m in r.violations
	contains(m, "FAIL-CLOSED - facts 'input.nist_sp_800_171_r2' were not supplied")

	# FAIL-CLOSED + 110 unattested requirements
	r.violation_count == 111
	r.requirements_attested == 0
}

test_non_object_root_fails_closed if {
	v := main.violations with input as {"nist_sp_800_171_r2": true}
	some m in v
	contains(m, "FAIL-CLOSED")
}

test_all_true_is_compliant if {
	inp := {"nist_sp_800_171_r2": {"requirements": _all}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.compliant == true
	r.violation_count == 0
	r.requirements_attested == 110
	r.basic_attested == 31
	r.derived_attested == 79
	r.families["3.14"].attested == 7
}

test_one_false_row_is_named_in_report if {
	inp := {"nist_sp_800_171_r2": {"requirements": object.union(_all, {"3.13.11": false})}}
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	r.families["3.13"].gaps == ["3.13.11"]
	r.families["3.13"].attested == 15
	some m in r.violations
	startswith(m, "NIST SP 800-171 Rev 2 3.13.11 (3.13 SYSTEM AND COMMUNICATIONS PROTECTION, derived):")
}

test_string_true_rejected_and_unknown_id_flagged if {
	inp := {"nist_sp_800_171_r2": {"requirements": object.union(_all, {"3.1.2": "true", "03.01.01": true})}}
	v := main.violations with input as inp
	count(v) == 2
	some m1 in v
	startswith(m1, "NIST SP 800-171 Rev 2 3.1.2 ")
	some m2 in v
	contains(m2, "unknown id 03.01.01")
}

test_malformed_requirements_container if {
	v := main.violations with input as {"nist_sp_800_171_r2": {"requirements": ["3.1.1"]}}
	some m in v
	contains(m, "must be an object")
	count(v) == 111
}
