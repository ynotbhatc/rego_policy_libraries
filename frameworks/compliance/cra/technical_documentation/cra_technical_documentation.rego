package cra.technical_documentation

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 28 + Annex VII
# Technical documentation requirements. Manufacturers must prepare and
# maintain technical documentation for every product before placing it
# on the market, and keep it available for 10 years (Art.28(4)).

default compliant := false

# Annex VII (1) — General product description
violation contains msg if {
    not input.technical_documentation.product_description.documented
    msg := "CRA Annex VII.1(a): General product description not documented"
}

violation contains msg if {
    not input.technical_documentation.product_description.intended_purpose
    msg := "CRA Annex VII.1(b): Intended purpose / use cases not documented"
}

violation contains msg if {
    not input.technical_documentation.product_description.support_period_declared
    msg := "CRA Annex VII.1(c): Declared support period not documented"
}

# Annex VII (2) — Risk assessment
violation contains msg if {
    not input.technical_documentation.risk_assessment.documented
    msg := "CRA Annex VII.2(a): Cybersecurity risk assessment not documented"
}

violation contains msg if {
    not input.technical_documentation.risk_assessment.threats_identified
    msg := "CRA Annex VII.2(b): Identified threats and threat actors not documented"
}

violation contains msg if {
    not input.technical_documentation.risk_assessment.mitigations_documented
    msg := "CRA Annex VII.2(c): Mitigations applied for each identified threat not documented"
}

# Annex VII (3) — Design and architecture
violation contains msg if {
    not input.technical_documentation.design.architecture_diagram
    msg := "CRA Annex VII.3(a): Architecture/design diagram of the product not provided"
}

violation contains msg if {
    not input.technical_documentation.design.cybersecurity_controls_mapped
    msg := "CRA Annex VII.3(b): Mapping of cybersecurity controls to essential requirements not provided"
}

# Annex VII (4) — Vulnerability handling process
violation contains msg if {
    not input.technical_documentation.vuln_process.documented
    msg := "CRA Annex VII.4: Vulnerability handling process documentation not included"
}

# Annex VII (5) — Software bill of materials
violation contains msg if {
    not input.technical_documentation.sbom.included
    msg := "CRA Annex VII.5: SBOM not included in technical documentation"
}

# Annex VII (6) — Test results
violation contains msg if {
    not input.technical_documentation.testing.results_documented
    msg := "CRA Annex VII.6(a): Cybersecurity testing/audit results not documented"
}

violation contains msg if {
    not input.technical_documentation.testing.third_party_assessment
    input.technical_documentation.product.classification in {"important_class_2", "critical"}
    msg := "CRA Annex VII.6(b): Third-party conformity assessment not documented (required for Important Class II / Critical products)"
}

# Annex VII (7) — Declaration of conformity
violation contains msg if {
    not input.technical_documentation.declaration_of_conformity.signed
    msg := "CRA Annex VII.7: EU Declaration of Conformity not signed"
}

# Article 28(4) — Retention
violation contains msg if {
    not input.technical_documentation.retention.maintained_10_years
    msg := "CRA Art.28(4): Technical documentation not retained for 10 years after product placed on market"
}

# Article 28(5) — Availability to authorities
violation contains msg if {
    not input.technical_documentation.retention.available_on_request
    msg := "CRA Art.28(5): Technical documentation not available to market surveillance authorities on request"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "Article 28 / Annex VII",
    "name":   "Technical documentation",
    "controls_evaluated": 15,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
