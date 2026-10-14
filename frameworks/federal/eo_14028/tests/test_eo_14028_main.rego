# Tests for eo_14028.main — Executive Order 14028 (May 12, 2021).
package eo_14028.main_test

import rego.v1

import data.eo_14028.main

_all := {id: true | some id, _ in main.directives}

_supplier_rows := {id: true | some id, c in main.directives; c.role in {"supplier", "either"}}

_agency_rows := {id: true | some id, c in main.directives; c.role in {"fceb", "agency", "either"}}

_non_fceb_agency_rows := {id: true | some id, c in main.directives; c.role in {"agency", "either"}}

test_table_counts if {
	count(main.directives) == 43
	count(_supplier_rows) == 22
	count(_agency_rows) == 22
	count(_non_fceb_agency_rows) == 16
	count({id | some id, c in main.directives; c.role == "fceb"}) == 6
	count({id | some id, c in main.directives; c.derived}) == 12
	count({id | some id, c in main.directives; c.s == "4"}) == 19
}

test_every_row_has_known_section_role_and_matching_cite if {
	count({id | some id, c in main.directives; not main.sections[c.s]}) == 0
	count({id | some id, c in main.directives; not c.role in {"fceb", "agency", "supplier", "either"}}) == 0
	count({id | some id, c in main.directives; not startswith(c.cite, c.s)}) == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.roles.is_supplier == "undeclared"

	# FAIL-CLOSED (no facts) + 3 undeclared roles; no role open, so no directive rows yet
	r.violation_count == 4
	some v in r.violations
	contains(v, "FAIL-CLOSED")
	r.directives_evaluated == 0
}

test_all_true_both_roles_is_compliant if {
	inp := {"eo_14028": {"is_agency": true, "is_fceb_agency": true, "is_supplier": true, "directives": _all}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.directives_evaluated == 43
	r.directives_attested == 43
}

test_supplier_only if {
	inp := {"eo_14028": {"is_agency": false, "is_fceb_agency": false, "is_supplier": true, "directives": _supplier_rows}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.directives_evaluated == 22
	r.sections["3"].directives == 0
}

test_agency_only if {
	inp := {"eo_14028": {"is_agency": false, "is_fceb_agency": true, "is_supplier": false, "directives": _agency_rows}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.directives_evaluated == 22
	r.sections["4"].directives == 4
}

test_neither_role_declared_false_is_compliant_with_nothing_to_attest if {
	r := main.compliance_report with input as {"eo_14028": {"is_agency": false, "is_fceb_agency": false, "is_supplier": false}}
	r.compliant == true
	r.directives_evaluated == 0
}

test_one_false_is_named if {
	inp := {"eo_14028": {"is_agency": true, "is_fceb_agency": true, "is_supplier": true, "directives": object.union(_all, {"4.e.vii": false})}}
	not main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.violation_count == 1
	r.sections["4"].gaps == ["4.e.vii"]
	some v in r.violations
	startswith(v, "EO 14028 4(e)(vii)")
	contains(v, "Software Bill of Materials")
}

test_unknown_id_is_a_violation if {
	inp := {"eo_14028": {"is_agency": true, "is_fceb_agency": true, "is_supplier": true, "directives": object.union(_all, {"4.s": true})}}
	not main.compliant with input as inp
	some v in main.violations with input as inp
	contains(v, "unknown id 4.s")
}

test_malformed_container_is_a_violation if {
	inp := {"eo_14028": {"is_agency": false, "is_fceb_agency": false, "is_supplier": false, "directives": ["3.d"]}}
	some v in main.violations with input as inp
	contains(v, "must be an object")
}

test_dated_obligations_carried if {
	r := main.compliance_report with input as {}
	r.dated_obligations["3.d_mfa_and_encryption_adopted"].due == "2021-11-08"
	r.dated_obligations["7.f_cdm_moa_with_cisa"].days == 75
}

test_non_fceb_agency_gets_agency_rows_but_not_fceb_rows if {
	inp := {"eo_14028": {"is_agency": true, "is_fceb_agency": false, "is_supplier": false, "directives": _non_fceb_agency_rows}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.directives_evaluated == 16
	r.sections["7"].gaps == []
	r.sections["7"].directives == 1
	not main.applicable["7.b"] with input as inp
	main.applicable["3.d"] with input as inp
}

test_non_object_container_is_fail_closed if {
	r := main.compliance_report with input as {"eo_14028": "yes"}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
}
