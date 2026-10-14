# Tests for BSI C5:2026 Identity and Access Management (IAM).
package bsi_c5.identity_access_management_test

import rego.v1

import data.bsi_c5.identity_access_management as area

_all_true := {"bsi_c5": {"criteria": {id: true | some id, _ in area.criteria}}}

test_criteria_count_pinned if {
	count(area.criteria) == 9
}

test_subcriteria_counts_pinned if {
	sum([count(c.basic) | some c in area.criteria]) == 49
	sum([count(c.additional_sharpening) | some c in area.criteria]) == 6
	sum([count(c.additional_complementing) | some c in area.criteria]) == 14
}

test_ids_carry_area_prefix if {
	every id, _ in area.criteria { startswith(id, "IAM-") }
}

test_empty_input_every_criterion_fails if {
	r := area.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 9
	r.criteria_satisfied == 0
}

test_all_attested_compliant if {
	r := area.compliance_report with input as _all_true
	r.compliant == true
	r.violation_count == 0
	r.criteria_satisfied == 9
	r.gaps == []
}

test_one_false_named if {
	inp := json.patch(_all_true, [{"op": "replace", "path": "/bsi_c5/criteria/IAM-09", "value": false}])
	r := area.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	r.gaps == ["IAM-09"]
	some msg in r.violations
	contains(msg, "IAM-09")
}

test_truthy_non_boolean_is_not_attested if {
	inp := json.patch(_all_true, [{"op": "replace", "path": "/bsi_c5/criteria/IAM-01", "value": "yes"}])
	r := area.compliance_report with input as inp
	r.compliant == false
	r.gaps == ["IAM-01"]
}

test_basis_is_attestation if {
	r := area.compliance_report with input as {}
	r.criteria["IAM-01"].basis == "attestation"
	r.criteria["IAM-01"].satisfied == false
}
