package cra.oss_steward

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 24
# Open-source software stewards.
#
# CRA introduces a new category: a legal person (other than a natural
# person) that provides systematic, sustained support for the development
# of an open-source product with digital elements made available on the
# EU market for commercial activities. Stewards have a lighter-touch set
# of obligations than full manufacturers.
#
# Article 24(1) — Apply a cybersecurity policy to foster secure development
# Article 24(2) — Cooperate with market surveillance to mitigate risks
# Article 24(3) — Comply with reporting obligations in Article 14

default compliant := false

# Threshold — the steward classification only applies if the entity
# meets the "systematic and sustained" definition AND the OSS product
# is "intended for commercial activities".
applies_to_entity if {
    input.oss_steward.is_legal_person_other_than_natural
    input.oss_steward.provides_systematic_sustained_support
    input.oss_steward.oss_product_intended_for_commercial_activities
}

# Art.24(1) — Cybersecurity policy required
violation contains msg if {
    applies_to_entity
    not input.oss_steward.cybersecurity_policy.documented
    msg := "CRA Art.24(1): OSS steward has not documented a cybersecurity policy fostering voluntary development of secure products"
}

violation contains msg if {
    applies_to_entity
    not input.oss_steward.cybersecurity_policy.published
    msg := "CRA Art.24(1): OSS steward's cybersecurity policy is not published / publicly accessible"
}

violation contains msg if {
    applies_to_entity
    not input.oss_steward.cybersecurity_policy.covers_vulnerability_handling
    msg := "CRA Art.24(1): OSS steward's cybersecurity policy does not cover effective handling of vulnerabilities"
}

violation contains msg if {
    applies_to_entity
    not input.oss_steward.cybersecurity_policy.covers_secure_development_practices
    msg := "CRA Art.24(1): OSS steward's cybersecurity policy does not foster secure development practices"
}

# Art.24(2) — Cooperate with market surveillance authorities
violation contains msg if {
    applies_to_entity
    not input.oss_steward.cooperation.with_market_surveillance
    msg := "CRA Art.24(2): OSS steward has not committed to cooperate with market surveillance authorities to mitigate cyber risks"
}

violation contains msg if {
    applies_to_entity
    not input.oss_steward.cooperation.responds_to_authority_requests
    msg := "CRA Art.24(2): OSS steward does not respond to information requests from competent authorities"
}

# Art.24(3) — Reporting obligations under Article 14 apply
violation contains msg if {
    applies_to_entity
    input.oss_steward.actively_exploited_vuln_known == true
    input.oss_steward.hours_since_aware > 24
    not input.oss_steward.early_warning_to_enisa_sent
    msg := "CRA Art.24(3) / Art.14: OSS steward aware of actively exploited vulnerability has not sent 24h early warning to ENISA"
}

violation contains msg if {
    applies_to_entity
    input.oss_steward.actively_exploited_vuln_known == true
    input.oss_steward.hours_since_aware > 72
    not input.oss_steward.vulnerability_notification_sent
    msg := "CRA Art.24(3) / Art.14: OSS steward has not sent the 72h vulnerability notification"
}

violation contains msg if {
    applies_to_entity
    input.oss_steward.severe_incident_occurred == true
    input.oss_steward.hours_since_incident > 24
    not input.oss_steward.severe_incident_early_warning_sent
    msg := "CRA Art.24(3) / Art.14: OSS steward has not reported a severe incident to ENISA within 24h"
}

# Art.24 — Engage with affected downstream manufacturers
violation contains msg if {
    applies_to_entity
    input.oss_steward.actively_exploited_vuln_known == true
    not input.oss_steward.downstream_manufacturers_engaged
    msg := "CRA Art.24: OSS steward has not engaged with downstream manufacturers using the affected component"
}

# Art.24 — Provide a coordinated vulnerability disclosure (CVD) policy
violation contains msg if {
    applies_to_entity
    not input.oss_steward.cvd_policy.published
    msg := "CRA Art.24: OSS steward has not published a coordinated vulnerability disclosure (CVD) policy"
}

# Art.24 — Allow reporting of vulnerabilities through a documented channel
violation contains msg if {
    applies_to_entity
    not input.oss_steward.vulnerability_reporting_channel.exists
    msg := "CRA Art.24: OSS steward has not provided a documented channel for receiving vulnerability reports"
}

# Article 24 — Reduced documentation obligations: stewards do not need
# to perform full CRA conformity assessment, but they MUST keep records
# of significant security decisions.
violation contains msg if {
    applies_to_entity
    not input.oss_steward.record_keeping.security_decisions_documented
    msg := "CRA Art.24: OSS steward has not kept records of significant cybersecurity-related decisions"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "Article 24",
    "name":   "Open-source software steward obligations",
    "controls_evaluated": 13,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
