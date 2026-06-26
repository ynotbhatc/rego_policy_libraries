package cra.foss_exclusion

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 23 (recitals 15-18) + interaction with Art.24
# Free and open-source software exclusion.
#
# CRA does NOT apply to free + open-source software supplied "outside the
# course of a commercial activity". The challenge is that the boundary
# between "commercial" and "non-commercial" OSS is fact-specific:
#   - A single corporate sponsor providing paid support → commercial
#   - A foundation / nonprofit collecting donations to fund development →
#     case-by-case (recital 15)
#   - Individual maintainer accepting donations / sponsorship → typically
#     non-commercial (and therefore exempt)
#
# This module evaluates the boundary conditions. If the entity meets the
# non-commercial exclusion criteria, the policy returns ZERO violations
# regardless of what other CRA modules find — that is the correct outcome.
#
# Returns:
#   * `exempt = true` when Art.23 exclusion applies — no violations emitted
#   * `exempt = false` when CRA applies — violations emitted only if the
#     entity claimed exemption it isn't entitled to.

default compliant := true   # default is "no obligation" — exemption applies
default exempt := false

# ── Threshold conditions for the Art.23 exclusion ─────────────────────────

# Recital 15 — distinguishes the supplier from the user perspective.
exempt if {
    input.foss.is_open_source_product
    input.foss.outside_course_of_commercial_activity
}

# ── Misuse: claimed exemption but commercial markers are present ──────────

# An entity that asserts the FOSS exclusion while collecting commercial
# revenue (paid support, license fees, hosted SaaS) is misclassifying.
violation contains msg if {
    input.foss.claimed_exemption == true
    input.foss.revenue.paid_support_offered
    msg := "CRA Art.23 (mis-claim): FOSS exemption claimed, but the entity offers paid support — this is a commercial activity"
}

violation contains msg if {
    input.foss.claimed_exemption == true
    input.foss.revenue.license_fees_collected
    msg := "CRA Art.23 (mis-claim): FOSS exemption claimed, but the entity collects license/usage fees — this is a commercial activity"
}

violation contains msg if {
    input.foss.claimed_exemption == true
    input.foss.revenue.commercial_saas_hosting
    msg := "CRA Art.23 (mis-claim): FOSS exemption claimed, but the entity offers a commercial hosted version — this is a commercial activity"
}

# Donations on their own do NOT constitute commercial activity (recital 15)
# but combined with sustained employed development they may. Check pattern:
violation contains msg if {
    input.foss.claimed_exemption == true
    input.foss.revenue.donations_received
    input.foss.development.employed_developers_paid_from_donations
    input.foss.development.developers_full_time
    msg := "CRA Art.23 (boundary): Donation-funded full-time paid developers move the entity toward the OSS-steward category (Art.24), not the Art.23 exclusion"
}

# Recital 18 — single integrator placing FOSS-based commercial product on
# market does not benefit from the exclusion regardless of what the upstream
# OSS license says.
violation contains msg if {
    input.foss.claimed_exemption == true
    input.foss.distribution.integrated_into_commercial_product
    input.foss.distribution.distributed_in_eu_market
    msg := "CRA Recital 18: FOSS exemption does not apply when the software is integrated into a commercial product distributed on the EU market"
}

# ── Process documentation ─────────────────────────────────────────────────

violation contains msg if {
    input.foss.claimed_exemption == true
    not input.foss.process.exemption_basis_documented
    msg := "CRA Art.23: FOSS exemption claimed but the basis for the claim is not documented (no audit trail)"
}

violation contains msg if {
    input.foss.claimed_exemption == true
    not input.foss.process.exemption_basis_reviewed_annually
    msg := "CRA Art.23: FOSS exemption status is not reviewed annually — commercial relationships may change over time"
}

compliant if { count(violation) == 0 }

# Useful auxiliary field for downstream consumers.
exemption_status := {
    "claimed":  input.foss.claimed_exemption,
    "valid":    exempt,
    "misclaim": count(violation) > 0,
}

compliance_report := {
    "family": "Article 23",
    "name":   "Free and open-source software exclusion (boundary check)",
    "controls_evaluated": 8,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
    "exempt":   exempt,
    "exemption_status": exemption_status,
}
