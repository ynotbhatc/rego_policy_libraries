package cra.distributor_obligations

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 20
# Distributor obligations.
#
# Distributors making products with digital elements available on the EU
# market must act with due care to ensure those products comply with CRA.
# Article 21 also makes a distributor a "manufacturer" when they modify
# the product or sell it under their own name.

default compliant := false

# Art.20(1) — Verify before making the product available
violation contains msg if {
    not input.distributor.verification.ce_marking_present
    msg := "CRA Art.20(1)(a): Distributor has not verified CE marking before making the product available"
}

violation contains msg if {
    not input.distributor.verification.declaration_of_conformity_provided
    msg := "CRA Art.20(1)(b): Distributor has not verified that the Declaration of Conformity accompanies the product"
}

violation contains msg if {
    not input.distributor.verification.manufacturer_identification_clear
    msg := "CRA Art.20(1)(c): Distributor has not verified manufacturer name + contact info are clearly identified on the product"
}

violation contains msg if {
    not input.distributor.verification.importer_identification_clear
    input.distributor.product_is_imported == true
    msg := "CRA Art.20(1)(c): Distributor has not verified importer name + address are present on imported products"
}

violation contains msg if {
    not input.distributor.verification.user_instructions_provided
    msg := "CRA Art.20(1)(d): Distributor has not verified user instructions/information are provided with the product"
}

# Art.20(2) — Suspend availability when non-compliance suspected
violation contains msg if {
    input.distributor.non_conformity_suspected == true
    not input.distributor.action.availability_suspended
    msg := "CRA Art.20(2): Distributor has not suspended making the product available when non-conformity was suspected"
}

# Art.20(2) — Inform manufacturer + importer
violation contains msg if {
    input.distributor.non_conformity_suspected == true
    not input.distributor.action.manufacturer_informed
    msg := "CRA Art.20(2): Distributor has not informed the manufacturer of suspected non-conformity"
}

# Art.20(3) — Storage / transport must not jeopardise compliance
violation contains msg if {
    not input.distributor.handling.storage_preserves_compliance
    msg := "CRA Art.20(3): Storage or transport conditions risk jeopardising product compliance with essential requirements"
}

# Art.20(4) — Inform market surveillance on significant cyber risk
violation contains msg if {
    input.distributor.risk_awareness.significant_risk_known == true
    not input.distributor.risk_awareness.market_surveillance_informed
    msg := "CRA Art.20(4): Distributor has not informed market surveillance authorities of a known significant cybersecurity risk"
}

# Art.20(5) — Provide information + cooperate with authorities
violation contains msg if {
    not input.distributor.cooperation.provide_info_on_request
    msg := "CRA Art.20(5): Distributor not committed to providing requested information to market surveillance authorities"
}

violation contains msg if {
    not input.distributor.cooperation.cooperate_on_corrective_action
    msg := "CRA Art.20(5): Distributor not committed to cooperating on corrective action when requested"
}

# Art.20(6) — Corrective action / withdrawal when non-conformity confirmed
violation contains msg if {
    input.distributor.non_conformity_confirmed == true
    not input.distributor.corrective_action.taken
    msg := "CRA Art.20(6): Distributor has not taken corrective action on confirmed non-conforming products"
}

violation contains msg if {
    input.distributor.non_conformity_confirmed == true
    input.distributor.corrective_action.severity == "high"
    not input.distributor.corrective_action.withdrawal_or_recall
    msg := "CRA Art.20(6): Distributor has not withdrawn / recalled non-conforming product where the cyber risk requires it"
}

# Article 21 — Distributor becomes manufacturer when modifying or rebranding
violation contains msg if {
    input.distributor.product_modified_after_placement == true
    not input.distributor.assumed_manufacturer_obligations
    msg := "CRA Art.21: Distributor that modified the product has not assumed manufacturer obligations under Article 13"
}

violation contains msg if {
    input.distributor.sold_under_own_brand == true
    not input.distributor.assumed_manufacturer_obligations
    msg := "CRA Art.21: Distributor selling the product under its own name/trademark has not assumed manufacturer obligations"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "Article 20",
    "name":   "Distributor obligations",
    "controls_evaluated": 15,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
