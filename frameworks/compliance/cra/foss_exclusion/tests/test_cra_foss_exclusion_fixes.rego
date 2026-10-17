package cra.foss_exclusion_test

import rego.v1

# Validation fixes 2026-10-17: compliant can be false; undeclared claim / markers are violations.

m := data.cra.foss_exclusion

clean_claim := {"foss": {
	"claimed_exemption": true, "is_open_source_product": true, "not_made_available_in_course_of_commercial_activity": true,
	"revenue": {"paid_support_offered": false, "license_fees_collected": false, "commercial_saas_hosting": false, "use_conditioned_on_personal_data": false},
	"distribution": {"claimant_integrates_into_own_commercial_product": false, "distributed_in_eu_market": true},
	"process": {"exemption_basis_documented": true, "exemption_basis_reviewed_annually": true},
}}

test_foss_empty_input_not_compliant if {
	not m.compliant with input as {}
	some v in m.violation with input as {}
	contains(v, "applicability not determined")
}

test_foss_no_claim_declared_is_compliant if {
	m.compliant with input as {"foss": {"claimed_exemption": false}}
}

test_foss_clean_claim_is_compliant if {
	m.compliant with input as clean_claim
}

test_foss_misclaim_makes_compliant_false if {
	i := json.patch(clean_claim, [{"op": "replace", "path": "/foss/revenue/license_fees_collected", "value": true}])
	m.compliant == false with input as i
	r := m.compliance_report with input as i
	r.compliant == false
	r.violation_count == 1
}

test_foss_claim_with_undeclared_markers_is_violation if {
	every field in ["paid_support_offered", "license_fees_collected", "commercial_saas_hosting", "use_conditioned_on_personal_data"] {
		not m.compliant with input as json.remove(clean_claim, [concat("", ["/foss/revenue/", field])])
	}
}

test_foss_claim_with_undeclared_distribution_is_violation if {
	not m.compliant with input as json.remove(clean_claim, ["/foss/distribution"])
}
