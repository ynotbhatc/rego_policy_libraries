# Tests for cisa_ssdaf.main — CISA Secure Software Development Attestation Form v1.0.
package cisa_ssdaf.main_test

import rego.v1

import data.cisa_ssdaf.main

_all := {id: true | some id, _ in main.attestations; id != "III.signature"}

_in_scope := {
	"developed_after_2022_09_14": true,
	"major_version_change_after_2022_09_14": false,
	"continuous_delivery": false,
	"developed_by_federal_agency": false,
	"open_source_obtained_directly_by_agency": false,
	"freely_obtained_publicly_available": false,
}

_ceo := {"type": "ceo", "name": "<signatory>", "date": "2026-10-13"}

_full := {"cisa_ssdaf": {"scope": _in_scope, "attestations": _all, "signatory": _ceo}}

test_table_counts if {
	count(main.attestations) == 15
	count({id | some id, c in main.attestations; c.s == "1"}) == 7
	count({id | some id, c in main.attestations; c.s == "4"}) == 4
	count(main._flags) == 6
}

test_every_item_has_a_known_section if {
	count({id | some id, c in main.attestations; not main.sections[c.s]}) == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.attestation_required == true
	r.scope.continuous_delivery == "undeclared"

	# FAIL-CLOSED (no facts) + 6 undeclared scope flags + 15 items
	r.violation_count == 22
	some v in r.violations
	contains(v, "FAIL-CLOSED")
}

test_all_true_is_compliant if {
	main.compliant with input as _full
	r := main.compliance_report with input as _full
	r.items_evaluated == 15
	r.items_attested == 15
}

test_one_false_is_named if {
	inp := {"cisa_ssdaf": object.union(_full.cisa_ssdaf, {"attestations": object.union(_all, {"1c": false})})}
	not main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.violation_count == 1
	r.sections["1"].gaps == ["1c"]
	some v in r.violations
	startswith(v, "CISA SSDAF 1c")
	contains(v, "multi-factor")
}

test_unknown_id_is_a_violation if {
	inp := {"cisa_ssdaf": object.union(_full.cisa_ssdaf, {"attestations": object.union(_all, {"5": true})})}
	not main.compliant with input as inp
	some v in main.violations with input as inp
	contains(v, "unknown id 5")
}

test_malformed_container_is_a_violation if {
	inp := {"cisa_ssdaf": object.union(_full.cisa_ssdaf, {"attestations": ["1a"]})}
	some v in main.violations with input as inp
	contains(v, "must be an object")
}

test_unsigned_is_a_gap if {
	inp := {"cisa_ssdaf": {"scope": _in_scope, "attestations": _all}}
	r := main.compliance_report with input as inp
	r.sections.III.gaps == ["III.signature"]
}

test_3pao_alternative_satisfies_signature if {
	inp := {"cisa_ssdaf": {"scope": _in_scope, "attestations": _all, "signatory": {"type": "3pao", "assessment_attached": true}}}
	main.compliant with input as inp
}

test_3pao_without_attachment_fails if {
	inp := {"cisa_ssdaf": {"scope": _in_scope, "attestations": _all, "signatory": {"type": "3pao"}}}
	not main.compliant with input as inp
}

test_excluded_software_needs_no_attestation if {
	inp := {"cisa_ssdaf": {"scope": object.union(_in_scope, {"freely_obtained_publicly_available": true})}}
	r := main.compliance_report with input as inp
	r.attestation_required == false
	r.items_evaluated == 0
	r.compliant == true
}

test_out_of_scope_legacy_software_needs_no_attestation if {
	inp := {"cisa_ssdaf": {"scope": object.union(_in_scope, {"developed_after_2022_09_14": false})}}
	r := main.compliance_report with input as inp
	r.attestation_required == false
	r.compliant == true
}

test_partially_declared_scope_stays_required if {
	inp := {"cisa_ssdaf": {"scope": {"freely_obtained_publicly_available": true}}}
	r := main.compliance_report with input as inp
	r.attestation_required == true
	r.compliant == false
}

test_poam_is_reported_but_not_a_pass if {
	inp := {"cisa_ssdaf": object.union(_full.cisa_ssdaf, {
		"attestations": object.union(_all, {"3": false}),
		"poam": {"submitted": true, "practices_not_attested": ["3"]},
	})}
	r := main.compliance_report with input as inp
	r.poam.submitted == true
	r.poam.practices_not_attested == ["3"]
	r.compliant == false
}

test_rows_carry_ssdf_and_eo_mapping if {
	main.attestations["1e"].ssdf == ["PO.5.2"]
	main.attestations["4c"].eo == "4e(iv)"
	"RV.3.3" in main.attestations["4"].ssdf
}
