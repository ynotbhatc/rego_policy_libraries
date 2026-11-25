package cra.online_marketplace_numeric_guards_test

import rego.v1

test_non_number_takedown_hours_is_evidence_missing if {
	every v in ["1", null, "x"] {
		msgs := data.cra.online_marketplace.violation with input as {"online_marketplace": {
			"is_marketplace_provider": true,
			"products_offered": {"includes_products_with_digital_elements": true},
			"authority_takedown_order_received": true,
			"authority_takedown_order_hours_pending": v,
		}}
		"Marketplace due diligence (DSA/GPSR-derived, non-CRA): evidence missing — a takedown order was received but authority_takedown_order_hours_pending was not declared" in msgs
		every m in msgs {
			not contains(m, "pending)")
		}
	}
}

test_numeric_takedown_hours_still_late if {
	msgs := data.cra.online_marketplace.violation with input as {"online_marketplace": {
		"is_marketplace_provider": true,
		"products_offered": {"includes_products_with_digital_elements": true},
		"authority_takedown_order_received": true,
		"authority_takedown_order_hours_pending": 50,
	}}
	some m in msgs
	startswith(m, "Marketplace due diligence (DSA/GPSR-derived, non-CRA): Marketplace has not actioned an authority takedown order within 48h (current: 50h pending)")
}
