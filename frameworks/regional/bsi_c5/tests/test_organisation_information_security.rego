# Tests for BSI C5:2026 Organisation of Information Security (OIS).
package bsi_c5.organisation_information_security_test

import rego.v1

import data.bsi_c5.organisation_information_security as area

_all_true := {"bsi_c5": {"criteria": {id: true | some id, _ in area.criteria}}}

test_criteria_count_pinned if {
	count(area.criteria) == 10
}

test_subcriteria_counts_pinned if {
	sum([count(c.basic) | some c in area.criteria]) == 34
	sum([count(c.additional_sharpening) | some c in area.criteria]) == 2
	sum([count(c.additional_complementing) | some c in area.criteria]) == 5
}

test_ids_carry_area_prefix if {
	every id, _ in area.criteria { startswith(id, "OIS-") }
}

test_empty_input_every_criterion_fails if {
	r := area.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 10
	r.criteria_satisfied == 0
}

test_all_attested_compliant if {
	r := area.compliance_report with input as _all_true
	r.compliant == true
	r.violation_count == 0
	r.criteria_satisfied == 10
	r.gaps == []
}

test_one_false_named if {
	inp := json.patch(_all_true, [{"op": "replace", "path": "/bsi_c5/criteria/OIS-10", "value": false}])
	r := area.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	r.gaps == ["OIS-10"]
	some msg in r.violations
	contains(msg, "OIS-10")
}

test_truthy_non_boolean_is_not_attested if {
	inp := json.patch(_all_true, [{"op": "replace", "path": "/bsi_c5/criteria/OIS-01", "value": "yes"}])
	r := area.compliance_report with input as inp
	r.compliant == false
	r.gaps == ["OIS-01"]
}

test_basis_is_attestation if {
	r := area.compliance_report with input as {}
	r.criteria["OIS-01"].basis == "attestation"
	r.criteria["OIS-01"].satisfied == false
}
