package cra.foss_exclusion

import rego.v1

# EU Cyber Resilience Act (CRA) — free and open-source software scope
# boundary (Regulation (EU) 2024/2847, final OJ text).
#
# The final CRA has NO dedicated "FOSS exclusion article". The boundary
# operates through the scope machinery: Art. 3(22) defines 'making
# available on the market' as supply "in the course of a commercial
# activity", read with recitals 15 and 18:
#   - Recital 15: charging a price for the product, or for technical
#     support services where this does NOT serve only the recuperation
#     of actual costs, monetising a platform, or conditioning use on
#     personal data for other than security purposes → commercial.
#     Cost-recovering paid support is NOT commercial.
#   - Recital 18: how development was financed (donations included)
#     is NOT taken into account; not-for-profits stay non-commercial
#     provided earnings after costs fund not-for-profit objectives.
#     Supplying a FOSS component for integration by other
#     manufacturers is making available on the market ONLY if the
#     component is monetised by its ORIGINAL manufacturer — a
#     downstream manufacturer's commercial product does not void the
#     upstream supplier's exclusion.
#
# The commercial/non-commercial question is per PRODUCT (edition), not
# per entity: the same organisation can be a manufacturer for an
# enterprise edition and outside scope (or a steward) for the
# community edition of the same project.
#
# If the exclusion applies, the product is outside CRA scope and this
# module returns ZERO violations — an out-of-scope entity has no CRA
# obligations. Violations are emitted only when an asserted exemption
# conflicts with commercial markers (mis-claim detection), plus two
# self-assessment hygiene checks (library practice, not CRA duties).

default compliant := true # default is "no obligation" — exclusion applies

default exempt := false

# ── Threshold for the non-commercial exclusion (Art. 3(22), rec. 15/18) ────

exempt if {
	input.foss.is_open_source_product
	input.foss.not_made_available_in_course_of_commercial_activity
}

# ── Mis-claim: asserted exclusion vs commercial markers ────────────────────

# Paid support is commercial ONLY beyond cost recovery (recital 15; a
# reasonable salary / living expenses counts as cost recovery).
violation contains msg if {
	input.foss.claimed_exemption == true
	input.foss.revenue.paid_support_offered
	not input.foss.revenue.paid_support_cost_recovery_only == true
	msg := "CRA Art.3(22)/recital 15 (mis-claim): exclusion claimed, but paid technical support exceeds recuperation of actual costs — a commercial activity"
}

violation contains msg if {
	input.foss.claimed_exemption == true
	input.foss.revenue.license_fees_collected
	msg := "CRA Art.3(22)/recital 15 (mis-claim): exclusion claimed, but the entity charges a price for the product (license/usage fees) — a commercial activity"
}

violation contains msg if {
	input.foss.claimed_exemption == true
	input.foss.revenue.commercial_saas_hosting
	msg := "CRA Art.3(22)/recital 15 (mis-claim): exclusion claimed, but the entity monetises the product through a hosted/platform offering — a commercial activity"
}

violation contains msg if {
	input.foss.claimed_exemption == true
	input.foss.revenue.use_conditioned_on_personal_data
	msg := "CRA Art.3(22)/recital 15 (mis-claim): exclusion claimed, but use of the product is conditioned on processing personal data for purposes other than security — a commercial activity"
}

# The UPSTREAM supplier loses the exclusion only when it monetises the
# component itself. If the CLAIMANT integrates the FOSS into its own
# commercial product placed on the EU market, the exclusion cannot
# cover that commercial product (recital 18).
violation contains msg if {
	input.foss.claimed_exemption == true
	input.foss.distribution.claimant_integrates_into_own_commercial_product
	input.foss.distribution.distributed_in_eu_market
	msg := "CRA recital 18 (mis-claim): the claimant integrates this software into its own commercial product placed on the EU market — the exclusion does not cover that product"
}

# ── Self-assessment hygiene (library practice — NOT CRA obligations) ───────
# An out-of-scope entity has no CRA duties; documenting the basis for
# the claim is prudent practice for when the facts change.

violation contains msg if {
	input.foss.claimed_exemption == true
	not input.foss.process.exemption_basis_documented
	msg := "Scope hygiene (not a CRA obligation): exclusion claimed but the basis for the claim is not documented — no audit trail if commercial facts change"
}

violation contains msg if {
	input.foss.claimed_exemption == true
	not input.foss.process.exemption_basis_reviewed_annually
	msg := "Scope hygiene (not a CRA obligation): exclusion basis is not reviewed periodically — monetisation and distribution facts drift"
}

compliant if {
	count(violation) == 0
}

# Useful auxiliary field for downstream consumers.
exemption_status := {
	"claimed": object.get(input, ["foss", "claimed_exemption"], false),
	"valid": exempt,
	"misclaim": count(violation) > 0,
}

compliance_report := {
	"family": "Scope — Art.3(22), recitals 15/18",
	"name": "Free and open-source software exclusion (boundary check)",
	"controls_evaluated": 7,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
	"exempt": exempt,
	"exemption_status": exemption_status,
}
