package cra.user_information

import rego.v1

# EU Cyber Resilience Act (CRA) — Annex II
# Information and instructions to the user.
#
# Manufacturers must include this set of information with every product
# placed on the EU market. Granular check separate from Art.13(10), which
# only verifies the manufacturer provides "instructions" at all.

default compliant := false

# Annex II (1) — Manufacturer name, registered trade name, contact
violation contains msg if {
    not input.user_information.manufacturer.name_provided
    msg := "CRA Annex II.1: Manufacturer's name or registered trade name not included in user information"
}

violation contains msg if {
    not input.user_information.manufacturer.postal_address_provided
    msg := "CRA Annex II.1: Manufacturer's postal address not included in user information"
}

violation contains msg if {
    not input.user_information.manufacturer.electronic_contact_provided
    msg := "CRA Annex II.1: Manufacturer's electronic address or website not included in user information"
}

violation contains msg if {
    not input.user_information.manufacturer.contact_for_vulnerability_reports
    msg := "CRA Annex II.1: Single point of contact for vulnerability reports not provided"
}

# Annex II (2) — Single point of contact for cybersecurity-related queries
violation contains msg if {
    not input.user_information.single_point_of_contact.published
    msg := "CRA Annex II.2: Single point of contact for cybersecurity-related queries not published"
}

# Annex II (3) — Identifier (type/batch/serial/version) of the product
violation contains msg if {
    not input.user_information.product_identifier.type_provided
    msg := "CRA Annex II.3: Product type identifier not provided in user information"
}

violation contains msg if {
    not input.user_information.product_identifier.batch_or_serial_provided
    msg := "CRA Annex II.3: Batch or serial number not provided"
}

violation contains msg if {
    not input.user_information.product_identifier.version_provided
    msg := "CRA Annex II.3: Product version (software version, firmware) not provided"
}

# Annex II (4) — Intended purpose, including the security environment
violation contains msg if {
    not input.user_information.intended_purpose.described
    msg := "CRA Annex II.4: Intended purpose of the product not described in user information"
}

violation contains msg if {
    not input.user_information.intended_purpose.security_environment_specified
    msg := "CRA Annex II.4: Security environment / required operating conditions not specified"
}

# Annex II (5) — Cybersecurity properties
violation contains msg if {
    not input.user_information.cybersecurity_properties.described
    msg := "CRA Annex II.5: Cybersecurity properties of the product not described to users"
}

# Annex II (6) — Use-case-relevant risks/threats
violation contains msg if {
    not input.user_information.risks_and_threats.documented
    msg := "CRA Annex II.6: Use-case-relevant cybersecurity risks and threats not documented for the user"
}

# Annex II (7) — Where to find SBOM
violation contains msg if {
    not input.user_information.sbom_access.disclosed_to_user
    msg := "CRA Annex II.7: User information does not disclose where the SBOM can be obtained"
}

# Annex II (8) — Support period and end-of-support date
violation contains msg if {
    not input.user_information.support_period.disclosed
    msg := "CRA Annex II.8: Declared support period not disclosed in user information"
}

violation contains msg if {
    not input.user_information.support_period.end_of_support_date_disclosed
    msg := "CRA Annex II.8: End-of-support date not disclosed"
}

# Annex II (9) — Where to find security updates
violation contains msg if {
    not input.user_information.updates.access_method_disclosed
    msg := "CRA Annex II.9: Method for the user to access security updates not disclosed"
}

violation contains msg if {
    not input.user_information.updates.installation_instructions
    msg := "CRA Annex II.9: Instructions for installing security updates not provided"
}

# Annex II (10) — Secure decommissioning of the product
violation contains msg if {
    not input.user_information.decommissioning.guidance_provided
    msg := "CRA Annex II.10: Guidance on secure decommissioning (data wipe / device disposal) not provided"
}

# Annex II (11) — Languages
violation contains msg if {
    not input.user_information.languages.member_state_languages_covered
    msg := "CRA Annex II.11: User information not provided in the official language(s) of the EU Member States where the product is made available"
}

# Annex II (12) — Easily understandable to expected users
violation contains msg if {
    not input.user_information.readability.appropriate_for_users
    msg := "CRA Annex II.12: User information not written in a way easily understandable to its expected users"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "Annex II",
    "name":   "Information and instructions to the user",
    "controls_evaluated": 20,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
