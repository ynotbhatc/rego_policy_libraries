package cra.online_marketplace_test

import rego.v1

# Validation fixes 2026-10-17: critical severity, missing severity / sample size / takedown hours.

m := data.cra.online_marketplace

compliant_marketplace := {"online_marketplace": {
	"is_marketplace_provider": true,
	"products_offered": {"includes_products_with_digital_elements": true},
	"single_point_of_contact": {"designated_for_authorities": true, "designated_for_end_users": true},
	"cooperation": {"with_authorities_documented": true},
	"trader_due_diligence": {"identity_verified": true, "cra_compliance_attested": true},
	"random_checks": {"performed": true, "sample_size_pct": 5},
	"reporting_channel": {"exists_for_consumers": true},
	"process_documentation": {"cra_process_documented": true},
}}

test_marketplace_declared_non_provider_is_compliant if {
	m.compliant with input as {"online_marketplace": {"is_marketplace_provider": false}}
}

test_marketplace_fully_compliant if {
	m.compliant with input as compliant_marketplace
}

test_marketplace_critical_listing_must_be_removed if {
	i := json.patch(compliant_marketplace, [
		{"op": "add", "path": "/online_marketplace/non_compliant_listing_identified", "value": true},
		{"op": "add", "path": "/online_marketplace/manufacturer_notified", "value": true},
		{"op": "add", "path": "/online_marketplace/severity", "value": "critical"},
	])
	"Marketplace due diligence (DSA/GPSR-derived, non-CRA): marketplace has not removed a high-severity non-compliant listing" in m.violation with input as i
}

test_marketplace_identified_listing_without_severity_is_violation if {
	i := json.patch(compliant_marketplace, [
		{"op": "add", "path": "/online_marketplace/non_compliant_listing_identified", "value": true},
		{"op": "add", "path": "/online_marketplace/manufacturer_notified", "value": true},
	])
	not m.compliant with input as i
}

test_marketplace_random_checks_without_sample_size_is_violation if {
	i := json.remove(compliant_marketplace, ["/online_marketplace/random_checks/sample_size_pct"])
	not m.compliant with input as i
}

test_marketplace_tiny_sample_size_is_violation if {
	i := json.patch(compliant_marketplace, [{"op": "replace", "path": "/online_marketplace/random_checks/sample_size_pct", "value": 0.5}])
	not m.compliant with input as i
}

test_marketplace_takedown_without_hours_is_violation if {
	i := json.patch(compliant_marketplace, [{"op": "add", "path": "/online_marketplace/authority_takedown_order_received", "value": true}])
	not m.compliant with input as i
}
