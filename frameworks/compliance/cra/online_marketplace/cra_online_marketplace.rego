package cra.online_marketplace

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 22
# Obligations of providers of online marketplaces.
#
# Marketplaces (within the meaning of the Digital Services Act) that allow
# consumers to conclude distance contracts with traders for products with
# digital elements must support market surveillance and ensure non-compliant
# products can be removed quickly. The DSA framework also applies, but
# Article 22 sets cybersecurity-specific obligations.

default compliant := false

# Threshold gate — applies only to providers of online marketplaces.
applies if {
    input.online_marketplace.is_marketplace_provider
    input.online_marketplace.products_offered.includes_products_with_digital_elements
}

# Art.22(1) — Single point of contact for market surveillance authorities
violation contains msg if {
    applies
    not input.online_marketplace.single_point_of_contact.designated_for_authorities
    msg := "CRA Art.22(1): Online marketplace has not designated a single point of contact for market surveillance authorities"
}

# Art.22(1) — Single point of contact also for end-users
violation contains msg if {
    applies
    not input.online_marketplace.single_point_of_contact.designated_for_end_users
    msg := "CRA Art.22(1): Online marketplace has not designated a single point of contact for end users on cybersecurity matters"
}

# Art.22(2) — Cooperate with national authorities to ensure compliance
violation contains msg if {
    applies
    not input.online_marketplace.cooperation.with_authorities_documented
    msg := "CRA Art.22(2): Marketplace's cooperation process with national authorities not documented"
}

# Art.22(3) — Act on authority orders to remove illegal listings
violation contains msg if {
    applies
    input.online_marketplace.authority_takedown_order_received == true
    input.online_marketplace.authority_takedown_order_hours_pending > 48
    not input.online_marketplace.authority_takedown_order_actioned
    msg := sprintf("CRA Art.22(3): Marketplace has not actioned an authority takedown order within 48h (current: %dh pending)", [input.online_marketplace.authority_takedown_order_hours_pending])
}

# Art.22(4) — Trader identification (CRA-relevant info: traceability of the seller)
violation contains msg if {
    applies
    not input.online_marketplace.trader_due_diligence.identity_verified
    msg := "CRA Art.22(4): Marketplace has not verified the identity of traders offering products with digital elements"
}

violation contains msg if {
    applies
    not input.online_marketplace.trader_due_diligence.cra_compliance_attested
    msg := "CRA Art.22(4): Marketplace has not obtained trader attestation of CRA compliance before listing"
}

# Art.22(5) — Random sampling / checks
violation contains msg if {
    applies
    not input.online_marketplace.random_checks.performed
    msg := "CRA Art.22(5): Marketplace has not implemented random checks for CRA non-compliance among offered products"
}

violation contains msg if {
    applies
    input.online_marketplace.random_checks.performed == true
    input.online_marketplace.random_checks.sample_size_pct < 1.0
    msg := sprintf("CRA Art.22(5): Marketplace random-check sample size (%v%%) is below a defensible threshold (1%% min)", [input.online_marketplace.random_checks.sample_size_pct])
}

# Art.22 — Where compliance issue identified, manufacturer notified + listing handled
violation contains msg if {
    applies
    input.online_marketplace.non_compliant_listing_identified == true
    not input.online_marketplace.manufacturer_notified
    msg := "CRA Art.22: Marketplace identified non-compliant listing but did not notify the manufacturer/seller"
}

violation contains msg if {
    applies
    input.online_marketplace.non_compliant_listing_identified == true
    input.online_marketplace.severity == "high"
    not input.online_marketplace.listing_removed
    msg := "CRA Art.22: Marketplace has not removed a high-severity non-compliant listing"
}

# Art.22 — End-user information on identified non-compliance affecting them
violation contains msg if {
    applies
    input.online_marketplace.non_compliant_listing_identified == true
    input.online_marketplace.buyers_affected == true
    not input.online_marketplace.affected_buyers_notified
    msg := "CRA Art.22: Marketplace has not notified buyers affected by a previously-sold non-compliant product"
}

# Art.22 — Marketplace must publish a CRA-specific reporting channel
violation contains msg if {
    applies
    not input.online_marketplace.reporting_channel.exists_for_consumers
    msg := "CRA Art.22: Marketplace has no published channel for consumers to report suspected CRA non-compliance"
}

# Internal process documentation
violation contains msg if {
    applies
    not input.online_marketplace.process_documentation.cra_process_documented
    msg := "CRA Art.22: Marketplace has not documented its CRA-compliance process for traders + products"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "Article 22",
    "name":   "Online marketplace obligations",
    "controls_evaluated": 13,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
