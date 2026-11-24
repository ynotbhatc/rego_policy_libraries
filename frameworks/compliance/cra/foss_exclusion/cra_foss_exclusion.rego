# METADATA
# title: "EU Cyber Resilience Act (CRA) — free and open-source software scope"
# custom:
#   class: compliance
#   framework: cra
#   source: eu
#   domains: [eu, product-security]
#   coverage:
#     checks: 10
#     cited: 4
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
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

# `default compliant := true` used to sit here: the rule below could then never make `compliant`
# false, because when violations existed the default still applied. The default is false; an
# entity that makes no exemption claim has no mis-claim to report and still reaches compliant via
# the rule below (the exclusion boundary is conditional-applicability: "no claim" = no obligation).
# Decisions 2026-10-19: `claimed_exemption` must be declared (false = no claim, no obligation), and a
# claimed exemption must declare every commercial marker (an undeclared marker is not "false").
default compliant := false

default exempt := false

# ── Threshold for the non-commercial exclusion (Art. 3(22), rec. 15/18) ────

exempt if {
	input.foss.is_open_source_product == true
	input.foss.not_made_available_in_course_of_commercial_activity == true
}

# ── Applicability and marker declarations ──────────────────────────────────

violation contains "CRA Art.3(22): applicability not determined — foss.claimed_exemption not declared" if {
	not is_boolean(object.get(object.get(_root, "foss", {}), "claimed_exemption", null))
}

# A claimed exclusion rests on the two Art. 3(22) threshold facts; they must be stated as true or false.
violation contains msg if {
	input.foss.claimed_exemption == true
	some field in ["is_open_source_product", "not_made_available_in_course_of_commercial_activity"]
	msg := sprintf("CRA Art.3(22): exclusion claimed — %s", [_problem(_root, ["foss", field])])
}

commercial_markers := [
	["revenue", "paid_support_offered"],
	["revenue", "license_fees_collected"],
	["revenue", "commercial_saas_hosting"],
	["revenue", "use_conditioned_on_personal_data"],
	["distribution", "claimant_integrates_into_own_commercial_product"],
	["distribution", "distributed_in_eu_market"],
]

violation contains msg if {
	input.foss.claimed_exemption == true
	some m in commercial_markers
	not is_boolean(object.get(input.foss, m, null))
	msg := sprintf("CRA Art.3(22) (evidence missing): exclusion claimed but commercial marker foss.%s not declared", [concat(".", m)])
}

# ── Mis-claim: asserted exclusion vs commercial markers ────────────────────

# Paid support is commercial ONLY beyond cost recovery (recital 15; a
# reasonable salary / living expenses counts as cost recovery).
violation contains msg if {
	input.foss.claimed_exemption == true
	input.foss.revenue.paid_support_offered == true
	note := _unmet(_root, ["foss", "revenue", "paid_support_cost_recovery_only"])
	text := "CRA Art.3(22)/recital 15 (mis-claim): exclusion claimed, but paid technical support exceeds recuperation of actual costs — a commercial activity"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.foss.claimed_exemption == true
	input.foss.revenue.license_fees_collected == true
	msg := "CRA Art.3(22)/recital 15 (mis-claim): exclusion claimed, but the entity charges a price for the product (license/usage fees) — a commercial activity"
}

violation contains msg if {
	input.foss.claimed_exemption == true
	input.foss.revenue.commercial_saas_hosting == true
	msg := "CRA Art.3(22)/recital 15 (mis-claim): exclusion claimed, but the entity monetises the product through a hosted/platform offering — a commercial activity"
}

violation contains msg if {
	input.foss.claimed_exemption == true
	input.foss.revenue.use_conditioned_on_personal_data == true
	msg := "CRA Art.3(22)/recital 15 (mis-claim): exclusion claimed, but use of the product is conditioned on processing personal data for purposes other than security — a commercial activity"
}

# The UPSTREAM supplier loses the exclusion only when it monetises the
# component itself. If the CLAIMANT integrates the FOSS into its own
# commercial product placed on the EU market, the exclusion cannot
# cover that commercial product (recital 18).
violation contains msg if {
	input.foss.claimed_exemption == true
	input.foss.distribution.claimant_integrates_into_own_commercial_product == true
	input.foss.distribution.distributed_in_eu_market == true
	msg := "CRA recital 18 (mis-claim): the claimant integrates this software into its own commercial product placed on the EU market — the exclusion does not cover that product"
}

# ── Self-assessment hygiene (library practice — NOT CRA obligations) ───────
# An out-of-scope entity has no CRA duties; documenting the basis for
# the claim is prudent practice for when the facts change.

violation contains msg if {
	input.foss.claimed_exemption == true
	note := _unmet(_root, ["foss", "process", "exemption_basis_documented"])
	text := "Scope hygiene (not a CRA obligation): exclusion claimed but the basis for the claim is not documented — no audit trail if commercial facts change"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.foss.claimed_exemption == true
	note := _unmet(_root, ["foss", "process", "exemption_basis_reviewed_annually"])
	text := "Scope hygiene (not a CRA obligation): exclusion basis is not reviewed periodically — monetisation and distribution facts drift"
	msg := concat("", [text, note])
}

compliant if {
	count(violation) == 0
}

# Useful auxiliary field for downstream consumers.
exemption_status := {
	"claimed": object.get(_root, ["foss", "claimed_exemption"], false),
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
