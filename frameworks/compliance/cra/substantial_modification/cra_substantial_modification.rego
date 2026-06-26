package cra.substantial_modification

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 11
# Substantial modifications.
#
# When a product undergoes a "substantial modification" — changes the
# intended use, affects compliance with essential requirements, or alters
# the risk profile — the modifier becomes legally responsible as a
# manufacturer and must re-perform conformity assessment.
#
# Key implications: cybersecurity-relevant feature changes, new connectivity
# capability, change of supported platforms, additions to the SBOM, or
# functional changes that affect threat exposure are all triggers.

default compliant := false

# Art.11(1) — Identify modifications that constitute "substantial"
violation contains msg if {
    not input.substantial_modification.assessment_process.documented
    msg := "CRA Art.11(1): No documented process to assess whether a planned change constitutes a substantial modification"
}

violation contains msg if {
    not input.substantial_modification.assessment_process.criteria_published
    msg := "CRA Art.11(1): Substantial-modification assessment criteria not published / documented"
}

# Art.11(2) — Re-assess conformity after substantial modification
violation contains msg if {
    input.substantial_modification.modification_classified_substantial == true
    not input.substantial_modification.conformity_reassessment.performed
    msg := "CRA Art.11(2): A modification was classified as substantial but conformity assessment has not been re-performed"
}

violation contains msg if {
    input.substantial_modification.modification_classified_substantial == true
    not input.substantial_modification.conformity_reassessment.scope_appropriate
    msg := "CRA Art.11(2): Re-performed conformity assessment scope does not cover the modified aspects of the product"
}

# Art.11(3) — Modifier assumes manufacturer's obligations
violation contains msg if {
    input.substantial_modification.modification_classified_substantial == true
    input.substantial_modification.modifier_is_not_original_manufacturer == true
    not input.substantial_modification.modifier_assumed_manufacturer_obligations
    msg := "CRA Art.11(3): Modifier of a substantially-modified product has not assumed manufacturer obligations under Article 13"
}

# Connectivity changes — new attack surface
violation contains msg if {
    input.substantial_modification.changes.added_network_connectivity == true
    not input.substantial_modification.changes.risk_assessment_updated
    msg := "CRA Art.11 (Annex I.1 interaction): New network connectivity added without an updated cybersecurity risk assessment"
}

# Cryptographic primitive changes
violation contains msg if {
    input.substantial_modification.changes.cryptographic_primitive_changed == true
    not input.substantial_modification.changes.cryptographic_review_performed
    msg := "CRA Art.11 (Annex I.5/6 interaction): Cryptographic primitive changed without security review of the new mechanism"
}

# SBOM changes
violation contains msg if {
    input.substantial_modification.changes.sbom_changed == true
    not input.substantial_modification.changes.sbom_published_after_change
    msg := "CRA Art.11 (Annex II.1 interaction): SBOM not refreshed after dependency changes"
}

# Update technical documentation
violation contains msg if {
    input.substantial_modification.modification_classified_substantial == true
    not input.substantial_modification.documentation_updated
    msg := "CRA Art.11(2) / Art.28: Substantial modification performed but technical documentation not updated"
}

# Declaration of Conformity must be reissued
violation contains msg if {
    input.substantial_modification.modification_classified_substantial == true
    not input.substantial_modification.declaration_of_conformity_reissued
    msg := "CRA Art.11(2) / Annex IV: Substantial modification performed but Declaration of Conformity not reissued"
}

# Notify users of relevant security-impacting changes
violation contains msg if {
    input.substantial_modification.changes.security_relevant == true
    not input.substantial_modification.changes.users_notified
    msg := "CRA Art.11 / Annex II: Security-relevant substantial modification not communicated to existing users"
}

# Updates to support period commitment
violation contains msg if {
    input.substantial_modification.modification_classified_substantial == true
    not input.substantial_modification.support_period_recommitted
    msg := "CRA Art.11 / Art.13(8): Substantial modification did not re-affirm the declared support period for the modified product"
}

# Process maturity — review cadence
violation contains msg if {
    not input.substantial_modification.assessment_process.reviewed_annually
    msg := "CRA Art.11: Substantial-modification assessment criteria not reviewed at least annually"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "Article 11",
    "name":   "Substantial modifications",
    "controls_evaluated": 13,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
