package cra.essential_requirements

import rego.v1

# EU Cyber Resilience Act (CRA) — Annex I Part I
# Essential cybersecurity requirements for products with digital elements (PDE).
#
# These requirements apply to every product with digital elements placed on
# the EU market. Manufacturers must ensure compliance "by design" before
# CE marking is permitted (Articles 32-33).

default compliant := false

# Annex I Part I (1) — Security by design
violation contains msg if {
    not input.essential_requirements.security_by_design.threat_modeled
    msg := "CRA Annex I.1(a): Product not designed/developed with appropriate level of cybersecurity based on risk assessment"
}

violation contains msg if {
    not input.essential_requirements.security_by_design.documented_assessment
    msg := "CRA Annex I.1(b): Cybersecurity risk assessment not documented"
}

# Annex I Part I (2) — Secure default configuration
violation contains msg if {
    not input.essential_requirements.default_config.secure_out_of_box
    msg := "CRA Annex I.2(a): Product not delivered with a secure-by-default configuration"
}

violation contains msg if {
    not input.essential_requirements.default_config.allows_reset_to_secure_defaults
    msg := "CRA Annex I.2(b): Product does not allow reset to the original secure default configuration"
}

# Annex I Part I (3) — Vulnerability protection
violation contains msg if {
    not input.essential_requirements.vulnerability_protection.security_updates_distinct
    msg := "CRA Annex I.3(a): Security updates not delivered separately from feature updates"
}

violation contains msg if {
    not input.essential_requirements.vulnerability_protection.automatic_updates_default
    msg := "CRA Annex I.3(b): Automatic security update mechanism not available or not enabled by default"
}

# Annex I Part I (4) — Protection from unauthorized access
violation contains msg if {
    not input.essential_requirements.access_protection.authentication_state_of_the_art
    msg := "CRA Annex I.4(a): Authentication mechanisms not state-of-the-art (e.g., MFA, hardware-backed keys for sensitive functions)"
}

violation contains msg if {
    not input.essential_requirements.access_protection.identity_access_management
    msg := "CRA Annex I.4(b): Identity and access management controls not implemented"
}

# Annex I Part I (5) — Confidentiality protection
violation contains msg if {
    not input.essential_requirements.confidentiality.data_at_rest_encrypted
    msg := "CRA Annex I.5(a): Stored/personal data not protected by encryption or comparable mechanisms"
}

violation contains msg if {
    not input.essential_requirements.confidentiality.data_in_transit_encrypted
    msg := "CRA Annex I.5(b): Transmitted data not protected via state-of-the-art encryption"
}

# Annex I Part I (6) — Integrity protection
violation contains msg if {
    not input.essential_requirements.integrity.code_signing_enforced
    msg := "CRA Annex I.6(a): Product does not protect integrity of stored/transmitted code and configuration (no code signing)"
}

violation contains msg if {
    not input.essential_requirements.integrity.tamper_detection
    msg := "CRA Annex I.6(b): Tamper detection / anti-rollback mechanisms not implemented"
}

# Annex I Part I (7) — Data minimization
violation contains msg if {
    not input.essential_requirements.data_minimization.only_necessary_data_processed
    msg := "CRA Annex I.7: Product processes data beyond what is necessary for its intended use"
}

# Annex I Part I (8) — Availability protection
violation contains msg if {
    not input.essential_requirements.availability.dos_protection
    msg := "CRA Annex I.8(a): Product not protected against denial-of-service attacks affecting essential functions"
}

violation contains msg if {
    not input.essential_requirements.availability.essential_functions_preserved
    msg := "CRA Annex I.8(b): Essential functions not preserved during/after a security incident"
}

# Annex I Part I (9) — Limit attack surfaces
violation contains msg if {
    not input.essential_requirements.attack_surface.external_interfaces_minimized
    msg := "CRA Annex I.9: External interfaces and attack surfaces not minimized"
}

# Annex I Part I (10) — Mitigate exploitation impact
violation contains msg if {
    not input.essential_requirements.exploitation_mitigation.techniques_implemented
    msg := "CRA Annex I.10: Exploitation mitigation techniques (sandboxing, ASLR, control-flow integrity) not implemented"
}

# Annex I Part I (11) — Security-relevant data logging
violation contains msg if {
    not input.essential_requirements.logging.security_events_recorded
    msg := "CRA Annex I.11(a): Security-relevant events not recorded/monitored"
}

violation contains msg if {
    not input.essential_requirements.logging.user_can_opt_out
    msg := "CRA Annex I.11(b): User cannot opt out of non-essential logging (privacy violation)"
}

# Annex I Part I (12) — Secure data deletion
violation contains msg if {
    not input.essential_requirements.data_deletion.secure_erase_available
    msg := "CRA Annex I.12: Secure data deletion mechanism (factory reset / cryptographic erase) not provided"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "Annex I Part I",
    "name":   "Essential cybersecurity requirements",
    "controls_evaluated": 21,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
