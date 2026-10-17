package cra.foss_exclusion_test

import rego.v1

# Validation fixes 2026-10-17: `default compliant := true` meant compliant could never be false.

m := data.cra.foss_exclusion

claim := {"foss": {
	"claimed_exemption": true, "is_open_source_product": true, "not_made_available_in_course_of_commercial_activity": true,
	"revenue": {"license_fees_collected": false},
	"process": {"exemption_basis_documented": true, "exemption_basis_reviewed_annually": true},
}}

test_foss_clean_claim_is_compliant if {
	m.compliant with input as claim
}

test_foss_no_claim_is_compliant_by_design if {
	m.compliant with input as {}
}

test_foss_misclaim_makes_compliant_false if {
	i := json.patch(claim, [{"op": "replace", "path": "/foss/revenue/license_fees_collected", "value": true}])
	m.compliant == false with input as i
	r := m.compliance_report with input as i
	r.compliant == false
	r.violation_count == 1
}

test_foss_hygiene_gap_makes_compliant_false if {
	i := json.patch(claim, [{"op": "replace", "path": "/foss/process/exemption_basis_documented", "value": false}])
	m.compliant == false with input as i
}
