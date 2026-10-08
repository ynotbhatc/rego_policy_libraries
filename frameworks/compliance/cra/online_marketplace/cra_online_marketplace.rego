# METADATA
# title: "Online marketplace due diligence for products with digital elements — NON-CRA ADJUNCT MODULE"
# custom:
#   class: compliance
#   framework: cra
#   source: eu
#   domains: [eu, product-security]
package cra.online_marketplace

import rego.v1

# Online marketplace due diligence for products with digital elements —
# NON-CRA ADJUNCT MODULE.
#
# The final CRA (Regulation (EU) 2024/2847) defines NO economic-operator
# category for online marketplaces: recital 78 notes that providers of
# pure intermediation services do not qualify as any of the Regulation's
# operator types (the final Art. 22 is substantial modification). The
# checks below derive from the adjacent EU framework that DOES bind
# marketplaces — the Digital Services Act and the General Product
# Safety Regulation (GPSR Art. 22) — applied to listings of products
# with digital elements. They are useful marketplace due diligence for
# CRA-regulated products, not CRA obligations.

default compliant := false

# Threshold gate — applies only to providers of online marketplaces.
applies if {
	input.online_marketplace.is_marketplace_provider
	input.online_marketplace.products_offered.includes_products_with_digital_elements
}

# Single point of contact for market surveillance authorities
violation contains msg if {
	applies
	not input.online_marketplace.single_point_of_contact.designated_for_authorities
	msg := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): Online marketplace has not designated a single point of contact for market surveillance authorities"
}

# Single point of contact also for end-users
violation contains msg if {
	applies
	not input.online_marketplace.single_point_of_contact.designated_for_end_users
	msg := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): Online marketplace has not designated a single point of contact for end users on cybersecurity matters"
}

# Cooperate with national authorities to ensure compliance
violation contains msg if {
	applies
	not input.online_marketplace.cooperation.with_authorities_documented
	msg := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): Marketplace's cooperation process with national authorities not documented"
}

# Act on authority orders to remove illegal listings
violation contains msg if {
	applies
	input.online_marketplace.authority_takedown_order_received == true
	input.online_marketplace.authority_takedown_order_hours_pending > 48
	not input.online_marketplace.authority_takedown_order_actioned
	msg := sprintf("Marketplace due diligence (DSA/GPSR-derived, non-CRA): Marketplace has not actioned an authority takedown order within 48h (current: %dh pending)", [input.online_marketplace.authority_takedown_order_hours_pending])
}

# Trader identification (CRA-relevant info: traceability of the seller)
violation contains msg if {
	applies
	not input.online_marketplace.trader_due_diligence.identity_verified
	msg := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): Marketplace has not verified the identity of traders offering products with digital elements"
}

violation contains msg if {
	applies
	not input.online_marketplace.trader_due_diligence.cra_compliance_attested
	msg := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): Marketplace has not obtained trader attestation of CRA compliance before listing"
}

# Random sampling / checks
violation contains msg if {
	applies
	not input.online_marketplace.random_checks.performed
	msg := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): Marketplace has not implemented random checks for CRA non-compliance among offered products"
}

violation contains msg if {
	applies
	input.online_marketplace.random_checks.performed == true
	input.online_marketplace.random_checks.sample_size_pct < 1.0
	msg := sprintf("Marketplace due diligence (DSA/GPSR-derived, non-CRA): Marketplace random-check sample size (%v%%) is below a defensible threshold (1%% min)", [input.online_marketplace.random_checks.sample_size_pct])
}

# Where compliance issue identified, manufacturer notified + listing handled
violation contains msg if {
	applies
	input.online_marketplace.non_compliant_listing_identified == true
	not input.online_marketplace.manufacturer_notified
	msg := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): marketplace identified non-compliant listing but did not notify the manufacturer/seller"
}

violation contains msg if {
	applies
	input.online_marketplace.non_compliant_listing_identified == true
	input.online_marketplace.severity == "high"
	not input.online_marketplace.listing_removed
	msg := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): marketplace has not removed a high-severity non-compliant listing"
}

# End-user information on identified non-compliance affecting them
violation contains msg if {
	applies
	input.online_marketplace.non_compliant_listing_identified == true
	input.online_marketplace.buyers_affected == true
	not input.online_marketplace.affected_buyers_notified
	msg := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): marketplace has not notified buyers affected by a previously-sold non-compliant product"
}

# Marketplace must publish a CRA-specific reporting channel
violation contains msg if {
	applies
	not input.online_marketplace.reporting_channel.exists_for_consumers
	msg := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): marketplace has no published channel for consumers to report suspected CRA non-compliance"
}

# Internal process documentation
violation contains msg if {
	applies
	not input.online_marketplace.process_documentation.cra_process_documented
	msg := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): marketplace has not documented its CRA-compliance process for traders + products"
}

compliant if count(violation) == 0

compliance_report := {
	"family": "Marketplace due diligence (non-CRA adjunct)",
	"name": "Online marketplace obligations",
	"controls_evaluated": 13,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
