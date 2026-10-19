package cra.foss_exclusion_test

import rego.v1

# Validation fixes 2026-10-17: `default compliant := true` meant compliant could never be false.

m := data.cra.foss_exclusion

claim := {"foss": {
	"claimed_exemption": true, "is_open_source_product": true, "not_made_available_in_course_of_commercial_activity": true,
	"revenue": {"paid_support_offered": false, "license_fees_collected": false, "commercial_saas_hosting": false, "use_conditioned_on_personal_data": false},
	"distribution": {"claimant_integrates_into_own_commercial_product": false, "distributed_in_eu_market": false},
	"process": {"exemption_basis_documented": true, "exemption_basis_reviewed_annually": true},
}}

test_foss_clean_claim_is_compliant if {
	m.compliant with input as claim
}

# decisions 2026-10-19: (name kept for test discovery) "no claim" must now be declared as claimed_exemption: false.
test_foss_no_claim_is_compliant_by_design if {
	m.compliant with input as {"foss": {"claimed_exemption": false}}
}

test_foss_undeclared_claim_status_is_a_violation if {
	not m.compliant with input as {}
	"CRA Art.3(22): applicability not determined — foss.claimed_exemption not declared" in m.violation with input as {}
}

test_foss_claim_with_undeclared_markers_is_a_violation if {
	i := {"foss": {"claimed_exemption": true, "process": {"exemption_basis_documented": true, "exemption_basis_reviewed_annually": true}}}
	not m.compliant with input as i
	count([x | some x in m.violation with input as i; contains(x, "commercial marker")]) == 6
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
