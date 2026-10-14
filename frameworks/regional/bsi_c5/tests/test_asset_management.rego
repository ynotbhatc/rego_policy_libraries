# Tests for BSI C5:2026 Asset Management (AM).
package bsi_c5.asset_management_test

import rego.v1

import data.bsi_c5.asset_management as area

_all_true := {"bsi_c5": {"criteria": {id: true | some id, _ in area.criteria}}}

test_criteria_count_pinned if {
	count(area.criteria) == 12
}

test_subcriteria_counts_pinned if {
	sum([count(c.basic) | some c in area.criteria]) == 26
	sum([count(c.additional_sharpening) | some c in area.criteria]) == 2
	sum([count(c.additional_complementing) | some c in area.criteria]) == 9
}

test_ids_carry_area_prefix if {
	every id, _ in area.criteria { startswith(id, "AM-") }
}

test_empty_input_every_criterion_fails if {
	r := area.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 12
	r.criteria_satisfied == 0
}

test_all_attested_compliant if {
	r := area.compliance_report with input as _all_true
	r.compliant == true
	r.violation_count == 0
	r.criteria_satisfied == 12
	r.gaps == []
}

test_one_false_named if {
	inp := json.patch(_all_true, [{"op": "replace", "path": "/bsi_c5/criteria/AM-12", "value": false}])
	r := area.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	r.gaps == ["AM-12"]
	some msg in r.violations
	contains(msg, "AM-12")
}

test_truthy_non_boolean_is_not_attested if {
	inp := json.patch(_all_true, [{"op": "replace", "path": "/bsi_c5/criteria/AM-01", "value": "yes"}])
	r := area.compliance_report with input as inp
	r.compliant == false
	r.gaps == ["AM-01"]
}

test_basis_is_attestation if {
	r := area.compliance_report with input as {}
	r.criteria["AM-01"].basis == "attestation"
	r.criteria["AM-01"].satisfied == false
}
