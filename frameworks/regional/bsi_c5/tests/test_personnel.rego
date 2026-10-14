# Tests for BSI C5:2026 Personnel (HR).
package bsi_c5.personnel_test

import rego.v1

import data.bsi_c5.personnel as area

_all_true := {"bsi_c5": {"criteria": {id: true | some id, _ in area.criteria}}}

test_criteria_count_pinned if {
	count(area.criteria) == 8
}

test_subcriteria_counts_pinned if {
	sum([count(c.basic) | some c in area.criteria]) == 28
	sum([count(c.additional_sharpening) | some c in area.criteria]) == 1
	sum([count(c.additional_complementing) | some c in area.criteria]) == 6
}

test_ids_carry_area_prefix if {
	every id, _ in area.criteria { startswith(id, "HR-") }
}

test_empty_input_every_criterion_fails if {
	r := area.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 8
	r.criteria_satisfied == 0
}

test_all_attested_compliant if {
	r := area.compliance_report with input as _all_true
	r.compliant == true
	r.violation_count == 0
	r.criteria_satisfied == 8
	r.gaps == []
}

test_one_false_named if {
	inp := json.patch(_all_true, [{"op": "replace", "path": "/bsi_c5/criteria/HR-08", "value": false}])
	r := area.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	r.gaps == ["HR-08"]
	some msg in r.violations
	contains(msg, "HR-08")
}

test_truthy_non_boolean_is_not_attested if {
	inp := json.patch(_all_true, [{"op": "replace", "path": "/bsi_c5/criteria/HR-01", "value": "yes"}])
	r := area.compliance_report with input as inp
	r.compliant == false
	r.gaps == ["HR-01"]
}

test_basis_is_attestation if {
	r := area.compliance_report with input as {}
	r.criteria["HR-01"].basis == "attestation"
	r.criteria["HR-01"].satisfied == false
}
