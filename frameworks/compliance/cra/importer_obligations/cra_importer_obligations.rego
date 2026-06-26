package cra.importer_obligations

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 19
# Importer obligations.
#
# Importers placing products with digital elements on the EU market must
# verify the manufacturer has met core CRA obligations before importing.
# In specific cases (Article 21) the importer is treated as a manufacturer
# and incurs the full Article 13 obligation set.

default compliant := false

# Art.19(1) — Verify manufacturer has performed conformity assessment
violation contains msg if {
    not input.importer.verification.conformity_assessment_performed
    msg := "CRA Art.19(1)(a): Importer has not verified that the manufacturer performed the required conformity assessment"
}

# Art.19(1) — Verify manufacturer has drawn up technical documentation
violation contains msg if {
    not input.importer.verification.technical_documentation_exists
    msg := "CRA Art.19(1)(b): Importer has not verified that technical documentation has been drawn up by the manufacturer"
}

# Art.19(1) — Verify CE marking and Declaration of Conformity
violation contains msg if {
    not input.importer.verification.ce_marking_present
    msg := "CRA Art.19(1)(c): Importer has not verified CE marking is affixed before placing the product on the market"
}

violation contains msg if {
    not input.importer.verification.declaration_of_conformity_accompanies_product
    msg := "CRA Art.19(1)(d): Declaration of Conformity does not accompany the imported product"
}

# Art.19(2) — Importer must indicate name/registered trade name/address on product
violation contains msg if {
    not input.importer.identification.name_on_product
    msg := "CRA Art.19(2)(a): Importer's name or registered trade name not indicated on the product (or packaging/accompanying documents)"
}

violation contains msg if {
    not input.importer.identification.postal_address_on_product
    msg := "CRA Art.19(2)(b): Importer's postal address not indicated on the product"
}

# Art.19(3) — Ensure storage/transport doesn't jeopardise compliance
violation contains msg if {
    not input.importer.handling.storage_transport_preserves_compliance
    msg := "CRA Art.19(3): Storage/transport conditions may jeopardise the product's compliance with essential requirements"
}

# Art.19(4) — Inform manufacturer + market surveillance of cybersecurity risk
violation contains msg if {
    input.importer.risk_awareness.product_presents_cyber_risk == true
    not input.importer.risk_awareness.manufacturer_informed
    msg := "CRA Art.19(4): Importer has not informed the manufacturer about a known cybersecurity risk in the product"
}

violation contains msg if {
    input.importer.risk_awareness.significant_risk == true
    not input.importer.risk_awareness.market_surveillance_informed
    msg := "CRA Art.19(4): Importer has not informed market surveillance authorities of a significant cybersecurity risk"
}

# Art.19(5) — Cooperate with authorities, provide info/documentation
violation contains msg if {
    not input.importer.cooperation.documentation_available_10_years
    msg := "CRA Art.19(5): Importer does not retain a copy of the Declaration of Conformity for 10 years"
}

violation contains msg if {
    not input.importer.cooperation.cooperate_with_authorities
    msg := "CRA Art.19(6): Importer not committed to cooperate with market surveillance authorities on request"
}

# Art.19(7) — Corrective action when non-conformity suspected
violation contains msg if {
    input.importer.non_conformity_known == true
    not input.importer.corrective_action.taken_immediately
    msg := "CRA Art.19(7): Importer has not taken immediate corrective action upon discovering non-conformity"
}

# Art.19(7) — Withdraw or recall non-conforming products
violation contains msg if {
    input.importer.non_conformity_known == true
    input.importer.corrective_action.severity == "high"
    not input.importer.corrective_action.withdrawal_or_recall_initiated
    msg := "CRA Art.19(7): Importer has not withdrawn or recalled a non-conforming product where the risk requires it"
}

# Article 21 — Importer treated as manufacturer when placing on market under own name
violation contains msg if {
    input.importer.placed_under_own_brand == true
    not input.importer.assumed_manufacturer_obligations
    msg := "CRA Art.21: Importer placing the product under its own name/trademark has not assumed manufacturer obligations under Article 13"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "Article 19",
    "name":   "Importer obligations",
    "controls_evaluated": 14,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
