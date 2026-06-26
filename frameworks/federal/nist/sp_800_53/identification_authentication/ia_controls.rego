package nist.sp800_53.identification_authentication

import rego.v1

# NIST SP 800-53 Rev 5 — Identification and Authentication (IA) Family
# Identify and authenticate users, devices, processes acting on behalf of users.

default compliant := false

violation contains msg if {
    not input.ia_controls.policy.documented
    msg := "NIST IA-1: Identification and authentication policy not documented"
}

violation contains msg if {
    not input.ia_controls.user_id_auth.uniquely_identified
    msg := "NIST IA-2: Organizational users not uniquely identified and authenticated"
}

violation contains msg if {
    not input.ia_controls.user_id_auth.mfa_for_privileged
    msg := "NIST IA-2(1): Multi-factor authentication not required for privileged accounts"
}

violation contains msg if {
    not input.ia_controls.user_id_auth.mfa_for_non_privileged
    msg := "NIST IA-2(2): Multi-factor authentication not required for non-privileged accounts"
}

violation contains msg if {
    not input.ia_controls.device_identification.implemented
    msg := "NIST IA-3: Device identification and authentication not implemented"
}

violation contains msg if {
    not input.ia_controls.identifier_management.unique_per_user
    msg := "NIST IA-4: Identifier management does not assign unique IDs per user"
}

violation contains msg if {
    not input.ia_controls.authenticator_management.complexity_enforced
    msg := "NIST IA-5: Authenticator management lacks complexity/lifetime enforcement"
}

violation contains msg if {
    not input.ia_controls.authenticator_management.encrypted_in_transit
    msg := "NIST IA-5(1): Authenticators not protected in transit"
}

violation contains msg if {
    not input.ia_controls.authenticator_management.encrypted_at_rest
    msg := "NIST IA-5(1): Stored authenticators not cryptographically protected at rest"
}

violation contains msg if {
    not input.ia_controls.authenticator_feedback.obscured
    msg := "NIST IA-6: Authenticator feedback (e.g., password entry) is not obscured"
}

violation contains msg if {
    not input.ia_controls.cryptographic_module_auth.fips_validated
    msg := "NIST IA-7: Cryptographic module authentication not FIPS-validated"
}

violation contains msg if {
    not input.ia_controls.non_organizational_users.identified
    msg := "NIST IA-8: Non-organizational users not uniquely identified and authenticated"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "IA",
    "name":   "Identification and Authentication",
    "controls_evaluated": 12,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
