package cra.conformity_assessment

import rego.v1

# EU Cyber Resilience Act (CRA) — Articles 32-33
# Conformity assessment procedures + CE marking.
#
# Product classification (Article 7 + Annex III):
#   - Default (most products)        → Module A (internal control)
#   - Important — Class I            → Module A or B+C
#   - Important — Class II           → Module B+C, B+D, or H (third-party notified body)
#   - Critical                       → European cybersecurity certification scheme (Art.8)

default compliant := false

# Article 32 — Conformity assessment procedure required
violation contains msg if {
    not input.conformity_assessment.procedure_selected
    msg := "CRA Art.32(1): Conformity assessment procedure not selected"
}

# Article 32(2) — Procedure must match product classification
violation contains msg if {
    input.conformity_assessment.product_class == "important_class_2"
    input.conformity_assessment.procedure_used == "module_a"
    msg := "CRA Art.32(2): Important Class II products require Module B+C, B+D, or H — Module A is insufficient"
}

violation contains msg if {
    input.conformity_assessment.product_class == "critical"
    not input.conformity_assessment.european_cyber_cert_scheme_used
    msg := "CRA Art.32(3) / Art.8: Critical products require certification under a European cybersecurity certification scheme"
}

# Article 32(4) — Notified body for third-party assessment
violation contains msg if {
    input.conformity_assessment.procedure_used in {"module_b_c", "module_b_d", "module_h"}
    not input.conformity_assessment.notified_body.engaged
    msg := "CRA Art.32(4): Third-party conformity assessment selected but no notified body engaged"
}

violation contains msg if {
    input.conformity_assessment.notified_body.engaged == true
    not input.conformity_assessment.notified_body.id_number
    msg := "CRA Art.32(4): Notified body ID number not recorded"
}

# Article 33 — CE marking
violation contains msg if {
    input.conformity_assessment.product_placed_on_market == true
    not input.conformity_assessment.ce_marking.affixed
    msg := "CRA Art.33(1): CE marking not affixed to product before placement on EU market"
}

violation contains msg if {
    input.conformity_assessment.ce_marking.affixed == true
    not input.conformity_assessment.ce_marking.visible_legible_indelible
    msg := "CRA Art.33(2): CE marking is not visible, legible, and indelible on the product"
}

violation contains msg if {
    input.conformity_assessment.procedure_used in {"module_b_c", "module_b_d", "module_h"}
    not input.conformity_assessment.ce_marking.notified_body_number_included
    msg := "CRA Art.33(4): Notified body identification number not included with CE marking (required when third-party assessment used)"
}

# Article 28(1) — EU Declaration of Conformity
violation contains msg if {
    not input.conformity_assessment.declaration_of_conformity.prepared
    msg := "CRA Art.28(1): EU Declaration of Conformity not prepared"
}

violation contains msg if {
    input.conformity_assessment.declaration_of_conformity.prepared == true
    not input.conformity_assessment.declaration_of_conformity.includes_required_elements
    msg := "CRA Art.28(1) / Annex IV: Declaration of Conformity missing required elements (product ID, manufacturer details, harmonised standards used, conformity statement)"
}

# Continuous compliance
violation contains msg if {
    not input.conformity_assessment.reassessment_on_substantial_modification
    msg := "CRA Art.32(5): Process not in place to re-assess conformity after substantial product modification"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "Articles 32-33",
    "name":   "Conformity assessment + CE marking",
    "controls_evaluated": 11,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
