package cra.oss_steward

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 24 (Regulation (EU) 2024/2847,
# final OJ text of 20 Nov 2024)
# Obligations of open-source software stewards.
#
# Art. 3(14): a steward is "a legal person, other than a manufacturer,
# that has the purpose or objective of systematically providing support
# on a sustained basis for the development of specific products with
# digital elements, qualifying as free and open-source software and
# intended for commercial activities, and that ensures the viability of
# those products". The same entity can be a manufacturer for one edition
# of a project and a steward for its community edition — the
# "other than a manufacturer" test is per product, not per entity.
#
# Art. 24(1) — put in place and document, in a verifiable manner, a
#              cybersecurity policy (vulnerability handling, secure
#              development, voluntary Art. 15 reporting, info sharing)
# Art. 24(2) — cooperate with market surveillance authorities; provide
#              the policy on reasoned request in a language the
#              authority can easily understand
# Art. 24(3) — Art. 14(1) (actively exploited vulnerability reporting)
#              applies ONLY to the extent the steward is involved in
#              the development; Art. 14(3)/(8) (severe incidents) apply
#              ONLY where the incident affects network and information
#              systems PROVIDED BY the steward for development.
#              The manufacturer hour-grid of Art. 14(2)/(4) is NOT
#              incorporated — stewards report "without undue delay".
# Art. 52(3) — ensure appropriate corrective action can be taken.
# Art. 64(10)(b) — administrative fines do NOT apply to steward
#              infringements (surfaced in the report, not a check).
#
# Input contract — input.oss_steward.* (all bool unless noted)
#   Threshold (Art. 3(14)):
#     is_legal_person, not_manufacturer_of_product,
#     provides_systematic_sustained_support, ensures_product_viability,
#     oss_product_intended_for_commercial_activities
#   Scope-of-duty facts (Art. 24(3) conditionality):
#     involved_in_development           — steward participates in the
#                                         product's development
#     provides_development_infrastructure — steward provides network/
#                                         information systems for it
#   Policy / cooperation / reporting facts: see the rules below.

default compliant := false

# Threshold — Art. 3(14). A steward classification applies only if ALL
# definition elements hold; entities below the threshold have no
# Article 24 obligations (most open-source projects have no steward).
applies_to_entity if {
	input.oss_steward.is_legal_person
	input.oss_steward.not_manufacturer_of_product
	input.oss_steward.provides_systematic_sustained_support
	input.oss_steward.ensures_product_viability
	input.oss_steward.oss_product_intended_for_commercial_activities
}

# ── Art. 24(1) — cybersecurity policy ───────────────────────────────────────

violation contains msg if {
	applies_to_entity
	not input.oss_steward.cybersecurity_policy.documented_verifiably
	msg := "CRA Art.24(1): OSS steward has not put in place and documented, in a verifiable manner, a cybersecurity policy (publication is the typical fulfilment; the obligation is verifiable documentation)"
}

violation contains msg if {
	applies_to_entity
	not input.oss_steward.cybersecurity_policy.covers_vulnerability_handling
	msg := "CRA Art.24(1): OSS steward's cybersecurity policy does not cover effective handling of vulnerabilities"
}

violation contains msg if {
	applies_to_entity
	not input.oss_steward.cybersecurity_policy.covers_secure_development_practices
	msg := "CRA Art.24(1): OSS steward's cybersecurity policy does not foster secure development of the supported products"
}

violation contains msg if {
	applies_to_entity
	not input.oss_steward.cybersecurity_policy.fosters_voluntary_reporting_and_sharing
	msg := "CRA Art.24(1): OSS steward's cybersecurity policy does not foster voluntary vulnerability reporting (Art.15) and the sharing of information on discovered vulnerabilities with the open-source community"
}

# Policy components — a CVD policy and a documented reporting channel
# are how the Art. 24(1) vulnerability-handling element is fulfilled.
violation contains msg if {
	applies_to_entity
	not input.oss_steward.cvd_policy.in_place
	msg := "CRA Art.24(1): OSS steward's policy lacks a coordinated vulnerability disclosure (CVD) component"
}

violation contains msg if {
	applies_to_entity
	not input.oss_steward.vulnerability_reporting_channel.exists
	msg := "CRA Art.24(1): OSS steward has no documented channel for receiving vulnerability reports from manufacturers and the community"
}

# ── Art. 24(2) — cooperation with market surveillance authorities ───────────

violation contains msg if {
	applies_to_entity
	not input.oss_steward.cooperation.with_market_surveillance
	msg := "CRA Art.24(2): OSS steward has not committed to cooperate with market surveillance authorities, at their request, to mitigate cybersecurity risks"
}

violation contains msg if {
	applies_to_entity
	not input.oss_steward.cooperation.policy_providable_on_reasoned_request
	msg := "CRA Art.24(2): OSS steward cannot provide its cybersecurity policy on a reasoned request, in a language easily understood by the requesting authority"
}

# ── Art. 24(3) — reporting, CONDITIONAL on the steward's role ───────────────
# Art. 14(1) applies only to the extent the steward is involved in the
# development; Art. 14(3)/(8) only where the severe incident affects
# network and information systems the steward provides for development.
# A steward providing non-technical support only has no reporting duty.

violation contains msg if {
	applies_to_entity
	input.oss_steward.involved_in_development == true
	input.oss_steward.actively_exploited_vuln_known == true
	not input.oss_steward.vulnerability_notified
	msg := "CRA Art.24(3)/Art.14(1): OSS steward involved in development is aware of an actively exploited vulnerability but has not notified it, without undue delay, simultaneously to the CSIRT designated as coordinator and to ENISA via the single reporting platform (Art.16)"
}

violation contains msg if {
	applies_to_entity
	input.oss_steward.provides_development_infrastructure == true
	input.oss_steward.severe_incident_affecting_provided_infrastructure == true
	not input.oss_steward.incident_notified
	msg := "CRA Art.24(3)/Art.14(3): a severe incident affects network and information systems the OSS steward provides for development, and it has not been notified, without undue delay, to the CSIRT designated as coordinator and to ENISA"
}

violation contains msg if {
	applies_to_entity
	input.oss_steward.provides_development_infrastructure == true
	input.oss_steward.severe_incident_affecting_provided_infrastructure == true
	not input.oss_steward.affected_users_informed
	msg := "CRA Art.24(3)/Art.14(8): users of the steward-provided systems affected by the severe incident have not been informed (where appropriate, including mitigations)"
}

# Reporting readiness — knowing the destination before the clock starts.
# Art. 14(1)/(7): the notification goes to the CSIRT designated as
# coordinator of the relevant Member State; identify it in advance
# (ORC WG practice: name it in SECURITY.md).
violation contains msg if {
	applies_to_entity
	not input.oss_steward.csirt_coordinator_identified
	msg := "CRA Art.14(1)/(7) readiness: OSS steward has not identified the CSIRT designated as coordinator that would receive its notifications"
}

# ── Art. 52(3) — corrective action ──────────────────────────────────────────

violation contains msg if {
	applies_to_entity
	not input.oss_steward.can_ensure_corrective_action
	msg := "CRA Art.52(3): OSS steward has no established means to ensure that appropriate corrective action is taken for the products it supports"
}

compliant if {
	count(violation) == 0
}

compliance_report := {
	"family": "Article 24",
	"name": "Open-source software steward obligations",
	"controls_evaluated": 13,
	"fines_note": "Art.64(10)(b): administrative fines do not apply to infringements by open-source software stewards",
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
