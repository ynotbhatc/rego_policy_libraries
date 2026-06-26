package cra.manufacturer_obligations

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 13
# General obligations on manufacturers of products with digital elements.

default compliant := false

# Article 13(1) — Compliance with essential requirements
violation contains msg if {
    not input.manufacturer.essential_requirements.met
    msg := "CRA Art.13(1): Manufacturer has not ensured compliance with the essential requirements in Annex I"
}

# Article 13(2) — Risk assessment performed
violation contains msg if {
    not input.manufacturer.risk_assessment.performed
    msg := "CRA Art.13(2): Manufacturer has not performed a cybersecurity risk assessment for the product"
}

# Article 13(3) — Risk assessment included in technical documentation
violation contains msg if {
    not input.manufacturer.risk_assessment.in_technical_documentation
    msg := "CRA Art.13(3): Risk assessment not included in the technical documentation"
}

# Article 13(4) — Vulnerability handling throughout product lifecycle
violation contains msg if {
    not input.manufacturer.vulnerability_handling.lifetime_coverage
    msg := "CRA Art.13(4): Vulnerability handling process does not cover the entire declared support period"
}

# Article 13(6) — Apply due diligence to integrated third-party components
violation contains msg if {
    not input.manufacturer.third_party_components.due_diligence_performed
    msg := "CRA Art.13(6): Due diligence not performed for integrated third-party components (open-source or commercial)"
}

violation contains msg if {
    not input.manufacturer.third_party_components.vulnerabilities_monitored
    msg := "CRA Art.13(6): Vulnerabilities in third-party components not actively monitored"
}

# Article 13(7) — Report exploited vulnerabilities + severe incidents to ENISA
# (Reporting timeline rules are in cra.incident_reporting; here we just check
# the obligation/awareness/process exists.)
violation contains msg if {
    not input.manufacturer.reporting.process_to_enisa_documented
    msg := "CRA Art.13(7) / 14: Process for reporting exploited vulnerabilities + severe incidents to ENISA not documented"
}

# Article 13(8) — Declared support period (also enforced in vulnerability_handling)
violation contains msg if {
    not input.manufacturer.support_period.declared
    msg := "CRA Art.13(8): Manufacturer has not declared a support period for the product"
}

violation contains msg if {
    input.manufacturer.support_period.years < 5
    msg := sprintf("CRA Art.13(8): Declared support period (%d years) is below the 5-year minimum", [input.manufacturer.support_period.years])
}

# Article 13(10) — User-facing instructions and information
violation contains msg if {
    not input.manufacturer.user_information.instructions_provided
    msg := "CRA Art.13(10): User instructions / information set not provided with the product"
}

violation contains msg if {
    not input.manufacturer.user_information.security_relevant_info_included
    msg := "CRA Art.13(10) / Annex II: User information missing security-relevant content (intended use, secure config guidance, support period, contact for vulnerability reporting)"
}

# Article 13(12) — Cooperation with market surveillance
violation contains msg if {
    not input.manufacturer.market_surveillance.cooperation_committed
    msg := "CRA Art.13(12): Manufacturer not committed to cooperate with market surveillance authorities upon request"
}

# Article 13(14) — End-of-support notification
violation contains msg if {
    not input.manufacturer.eol.end_of_support_notification_planned
    msg := "CRA Art.13(14): Plan to notify users at least 12 months before end-of-support not in place"
}

# Process maturity — internal cybersecurity governance for product teams
violation contains msg if {
    not input.manufacturer.governance.product_security_role_assigned
    msg := "CRA Art.13 (general): No designated product security role (PSIRT lead or equivalent) within the manufacturer"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "Article 13",
    "name":   "Manufacturer obligations",
    "controls_evaluated": 14,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
