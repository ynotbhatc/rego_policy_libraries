# METADATA
# title: "Online marketplace due diligence for products with digital elements — NON-CRA ADJUNCT MODULE"
# custom:
#   class: compliance
#   framework: cra
#   source: eu
#   domains: [eu, product-security]
#   coverage:
#     checks: 19
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
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
	input.online_marketplace.is_marketplace_provider == true
	input.online_marketplace.products_offered.includes_products_with_digital_elements == true
}

# Applicability (conditional-applicability gate): the checks below apply only to marketplace
# providers offering products with digital elements. Decisions 2026-10-19: both flags must be
# declared. An explicit `false` is "not applicable" (pass); an undeclared flag is "applicability
# not determined" (violation).
declared(name) if is_boolean(object.get(object.get(_root, "online_marketplace", {}), name, null))

declared_in_products(name) if is_boolean(object.get(object.get(object.get(_root, "online_marketplace", {}), "products_offered", {}), name, null))

violation contains "Marketplace due diligence (DSA/GPSR-derived, non-CRA): applicability not determined — is_marketplace_provider not declared" if {
	not declared("is_marketplace_provider")
}

violation contains "Marketplace due diligence (DSA/GPSR-derived, non-CRA): applicability not determined — products_offered.includes_products_with_digital_elements not declared" if {
	input.online_marketplace.is_marketplace_provider == true
	not declared_in_products("includes_products_with_digital_elements")
}

# Single point of contact for market surveillance authorities
violation contains msg if {
	applies
	note := _unmet(_root, ["online_marketplace", "single_point_of_contact", "designated_for_authorities"])
	text := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): Online marketplace has not designated a single point of contact for market surveillance authorities"
	msg := concat("", [text, note])
}

# Single point of contact also for end-users
violation contains msg if {
	applies
	note := _unmet(_root, ["online_marketplace", "single_point_of_contact", "designated_for_end_users"])
	text := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): Online marketplace has not designated a single point of contact for end users on cybersecurity matters"
	msg := concat("", [text, note])
}

# Cooperate with national authorities to ensure compliance
violation contains msg if {
	applies
	note := _unmet(_root, ["online_marketplace", "cooperation", "with_authorities_documented"])
	text := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): Marketplace's cooperation process with national authorities not documented"
	msg := concat("", [text, note])
}

# Act on authority orders to remove illegal listings
violation contains msg if {
	applies
	input.online_marketplace.authority_takedown_order_received == true
	is_number(input.online_marketplace.authority_takedown_order_hours_pending)
	input.online_marketplace.authority_takedown_order_hours_pending > 48
	note := _unmet(_root, ["online_marketplace", "authority_takedown_order_actioned"])
	text := sprintf("Marketplace due diligence (DSA/GPSR-derived, non-CRA): Marketplace has not actioned an authority takedown order within 48h (current: %dh pending)", [input.online_marketplace.authority_takedown_order_hours_pending])
	msg := concat("", [text, note])
}

violation contains "Marketplace due diligence (DSA/GPSR-derived, non-CRA): evidence missing — a takedown order was received but authority_takedown_order_hours_pending was not declared" if {
	applies
	input.online_marketplace.authority_takedown_order_received == true
	not is_number(object.get(input.online_marketplace, "authority_takedown_order_hours_pending", null))
}

# Trader identification (CRA-relevant info: traceability of the seller)
violation contains msg if {
	applies
	note := _unmet(_root, ["online_marketplace", "trader_due_diligence", "identity_verified"])
	text := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): Marketplace has not verified the identity of traders offering products with digital elements"
	msg := concat("", [text, note])
}

violation contains msg if {
	applies
	note := _unmet(_root, ["online_marketplace", "trader_due_diligence", "cra_compliance_attested"])
	text := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): Marketplace has not obtained trader attestation of CRA compliance before listing"
	msg := concat("", [text, note])
}

# Random sampling / checks
violation contains msg if {
	applies
	note := _unmet(_root, ["online_marketplace", "random_checks", "performed"])
	text := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): Marketplace has not implemented random checks for CRA non-compliance among offered products"
	msg := concat("", [text, note])
}

violation contains msg if {
	applies
	input.online_marketplace.random_checks.performed == true
	is_number(input.online_marketplace.random_checks.sample_size_pct)
	input.online_marketplace.random_checks.sample_size_pct < 1.0
	msg := sprintf("Marketplace due diligence (DSA/GPSR-derived, non-CRA): Marketplace random-check sample size (%v%%) is below a defensible threshold (1%% min)", [input.online_marketplace.random_checks.sample_size_pct])
}

violation contains "Marketplace due diligence (DSA/GPSR-derived, non-CRA): evidence missing — random_checks.performed is true but sample_size_pct was not declared" if {
	applies
	input.online_marketplace.random_checks.performed == true
	not is_number(object.get(input.online_marketplace.random_checks, "sample_size_pct", null))
}

# Where compliance issue identified, manufacturer notified + listing handled
violation contains msg if {
	applies
	input.online_marketplace.non_compliant_listing_identified == true
	note := _unmet(_root, ["online_marketplace", "manufacturer_notified"])
	text := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): marketplace identified non-compliant listing but did not notify the manufacturer/seller"
	msg := concat("", [text, note])
}

violation contains msg if {
	applies
	input.online_marketplace.non_compliant_listing_identified == true
	lower(input.online_marketplace.severity) in {"high", "critical"}
	note := _unmet(_root, ["online_marketplace", "listing_removed"])
	text := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): marketplace has not removed a high-severity non-compliant listing"
	msg := concat("", [text, note])
}

violation contains "Marketplace due diligence (DSA/GPSR-derived, non-CRA): evidence missing — a non-compliant listing was identified but its severity was not declared" if {
	applies
	input.online_marketplace.non_compliant_listing_identified == true
	not is_string(object.get(input.online_marketplace, "severity", null))
}

# End-user information on identified non-compliance affecting them
violation contains msg if {
	applies
	input.online_marketplace.non_compliant_listing_identified == true
	input.online_marketplace.buyers_affected == true
	note := _unmet(_root, ["online_marketplace", "affected_buyers_notified"])
	text := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): marketplace has not notified buyers affected by a previously-sold non-compliant product"
	msg := concat("", [text, note])
}

# Marketplace must publish a CRA-specific reporting channel
violation contains msg if {
	applies
	note := _unmet(_root, ["online_marketplace", "reporting_channel", "exists_for_consumers"])
	text := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): marketplace has no published channel for consumers to report suspected CRA non-compliance"
	msg := concat("", [text, note])
}

# Internal process documentation
violation contains msg if {
	applies
	note := _unmet(_root, ["online_marketplace", "process_documentation", "cra_process_documented"])
	text := "Marketplace due diligence (DSA/GPSR-derived, non-CRA): marketplace has not documented its CRA-compliance process for traders + products"
	msg := concat("", [text, note])
}

# ── Facts that switch an obligation on or off ───────────────────────────
# Each must be stated as true or false wherever its own condition holds. A missing, null or
# non-boolean value is an evidence problem and is reported; it is never read as "does not apply".
_conditions contains ["Marketplace due diligence (DSA/GPSR-derived, non-CRA)", ["online_marketplace", "authority_takedown_order_received"]] if applies

_conditions contains ["Marketplace due diligence (DSA/GPSR-derived, non-CRA)", ["online_marketplace", "non_compliant_listing_identified"]] if applies

_conditions contains ["Marketplace due diligence (DSA/GPSR-derived, non-CRA)", ["online_marketplace", "buyers_affected"]] if {
	applies
	input.online_marketplace.non_compliant_listing_identified == true
}

violation contains msg if {
	some [cite, path] in _conditions
	msg := sprintf("%s: applicability not determined — %s", [cite, _problem(_root, path)])
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

# ── Evidence helpers ─────────────────────────────────────────────────────────
# Evidence rule: only the boolean true passes a yes/no fact. _unmet is defined when the fact is not the
# boolean true; its value is appended to the finding and names the evidence problem (missing, null, or a
# value that is not a boolean, such as the strings "true" and "false"). A collected false adds nothing.
# _problem names the same evidence problem for a fact that switches an obligation on or off: such a fact
# must be stated as true or false and is never inferred from a missing field.
# The input document itself may be absent or not an object: every fact then reads as not collected.
default _root := {}

_root := input if is_object(input)

_fact(root, path) := value if {
	is_object(root)
	value := object.get(root, path, null)
} else := null

_problem(root, path) := sprintf("evidence missing: %s not collected", [concat(".", path)]) if _fact(root, path) == null

_problem(root, path) := sprintf("evidence invalid: %s is not a boolean (got %s)", [concat(".", path), type_name(_fact(root, path))]) if {
	_fact(root, path) != null
	not is_boolean(_fact(root, path))
}

_unmet(root, path) := "" if _fact(root, path) == false

_unmet(root, path) := concat("", [" — ", _problem(root, path)]) if not is_boolean(_fact(root, path))
