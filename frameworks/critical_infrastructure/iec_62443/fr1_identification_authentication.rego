package iec_62443.fr1

import rego.v1

# =============================================================================
# IEC 62443-3-3 FR 1 — Identification and Authentication Control (IAC)
#
# Purpose: Identify and authenticate all users (humans, software processes,
# and devices) before allowing them to access the IACS.
#
# Security Requirements (SRs):
#   SR 1.1  — Human user identification and authentication
#   SR 1.2  — Software process and device identification and authentication
#   SR 1.3  — Account management
#   SR 1.4  — Identifier management
#   SR 1.5  — Authenticator management
#   SR 1.6  — Wireless access management
#   SR 1.7  — Strength of password-based authentication
#   SR 1.8  — Public key infrastructure (PKI) certificates
#   SR 1.9  — Strength of public key authentication
#   SR 1.10 — Authenticator feedback
#   SR 1.11 — Unsuccessful login attempts
#   SR 1.12 — System use notification
#   SR 1.13 — Access via untrusted networks
#
# Input shape:
#   input.target_sl                            - int (1–4)
#   input.ics_systems[]
#     .name                                    - string
#     .unique_identification                   - bool
#     .mfa_enabled                             - bool
#     .default_credentials_unchanged           - bool
#     .password_min_length                     - int
#     .password_complexity                     - bool
#     .account_lockout_threshold               - int
#     .wireless_access                         - bool
#     .wireless_encrypted                      - bool
#     .system_use_notification                 - bool
#     .audit_logging_enabled                   - bool
#   input.authentication
#     .pki_or_certificate_based                - bool
#     .centralized_identity_management         - bool
#     .session_timeout_minutes                 - int
# =============================================================================

default compliant := false

# ---------------------------------------------------------------------------
# SR 1.1 — Human user identification and authentication
# All human users must be uniquely identified and authenticated before access.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.unique_identification
    msg := sprintf(
        "IEC 62443 SR 1.1 (IAC): ICS system '%v' does not enforce unique user identification. Every human user must have a unique identifier.",
        [system.name]
    )
}

# SR 1.1 RE 1 (SL 2+): Multi-factor authentication for all interfaces
violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    not system.mfa_enabled
    msg := sprintf(
        "IEC 62443 SR 1.1 RE 1 SL%v (IAC): ICS system '%v' does not enforce multi-factor authentication. MFA is required at Security Level 2+.",
        [input.target_sl, system.name]
    )
}

# SR 1.1 RE 2 (SL 3+): Hardware token-based authentication
violations contains msg if {
    input.target_sl >= 3
    not input.authentication.hardware_token_authentication
    msg := sprintf(
        "IEC 62443 SR 1.1 RE 2 SL%v (IAC): Hardware token-based authentication is not implemented. Required at Security Level 3+.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# SR 1.2 — Software process and device identification and authentication
# Software processes and devices must be identified and authenticated.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.device_authentication
    msg := sprintf(
        "IEC 62443 SR 1.2 (IAC): ICS system '%v' does not authenticate software processes or devices. Device-to-device authentication is required.",
        [system.name]
    )
}

# SR 1.2 RE 1 (SL 2+): Unique identification for all devices
violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    not system.device_unique_id
    msg := sprintf(
        "IEC 62443 SR 1.2 RE 1 SL%v (IAC): ICS system '%v' devices do not have unique identifiers. All IACS devices must have unique IDs at SL 2+.",
        [input.target_sl, system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 1.3 — Account management
# Manage accounts for human users, software processes, and devices.
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.authentication.centralized_identity_management
    msg := "IEC 62443 SR 1.3 (IAC): No centralized account management. IACS accounts must be centrally managed, reviewed, and deprovisioned promptly."
}

violations contains msg if {
    some system in input.ics_systems
    not system.account_review_process
    msg := sprintf(
        "IEC 62443 SR 1.3 (IAC): ICS system '%v' has no periodic account review process. Accounts must be reviewed regularly for continued business need.",
        [system.name]
    )
}

# SR 1.3 RE 1 (SL 2+): Unified account management policy
violations contains msg if {
    input.target_sl >= 2
    not input.authentication.unified_account_policy
    msg := sprintf(
        "IEC 62443 SR 1.3 RE 1 SL%v (IAC): No unified account management policy across all IACS components. Required at Security Level 2+.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# SR 1.4 — Identifier management
# Manage identifiers by uniqueness, re-use prevention, and revocation.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    system.default_credentials_unchanged
    msg := sprintf(
        "IEC 62443 SR 1.4 (IAC): ICS system '%v' uses unchanged default credentials. Default identifiers are a critical vulnerability — change all defaults before deployment.",
        [system.name]
    )
}

violations contains msg if {
    not input.authentication.identifier_reuse_prevented
    msg := "IEC 62443 SR 1.4 (IAC): IACS does not prevent identifier reuse for a defined period. Deactivated identifiers must not be reassigned for at least 90 days."
}

# ---------------------------------------------------------------------------
# SR 1.5 — Authenticator management
# Manage authenticators (passwords, tokens, keys) through their lifecycle.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.authenticator_lifecycle_managed
    msg := sprintf(
        "IEC 62443 SR 1.5 (IAC): ICS system '%v' has no authenticator lifecycle management. Passwords, keys, and tokens must have defined issuance, rotation, and revocation policies.",
        [system.name]
    )
}

violations contains msg if {
    not input.authentication.initial_authenticator_secure_distribution
    msg := "IEC 62443 SR 1.5 (IAC): Authenticators are not distributed via secure channels. Initial credentials must be delivered through a secure out-of-band mechanism."
}

# ---------------------------------------------------------------------------
# SR 1.6 — Wireless access management
# Authenticate wireless connections to the IACS.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    system.wireless_access == true
    not system.wireless_encrypted
    msg := sprintf(
        "IEC 62443 SR 1.6 (IAC): ICS system '%v' has unencrypted wireless access. All wireless connections to IACS must use strong authentication and encryption.",
        [system.name]
    )
}

violations contains msg if {
    some system in input.ics_systems
    system.wireless_access == true
    not system.wireless_authentication
    msg := sprintf(
        "IEC 62443 SR 1.6 (IAC): ICS system '%v' wireless access lacks authentication. Mutual authentication is required for all IACS wireless connections.",
        [system.name]
    )
}

violations contains msg if {
    not input.network.wireless_policy_documented
    msg := "IEC 62443 SR 1.6 (IAC): No wireless access policy for IACS. A documented policy defining allowed wireless use is required."
}

# ---------------------------------------------------------------------------
# SR 1.7 — Strength of password-based authentication
# Enforce minimum password strength requirements.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    system.password_min_length < 8
    msg := sprintf(
        "IEC 62443 SR 1.7 (IAC): ICS system '%v' has minimum password length of %v characters. Minimum 8 characters required (12+ recommended for SL 2+).",
        [system.name, system.password_min_length]
    )
}

violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    system.password_min_length < 12
    msg := sprintf(
        "IEC 62443 SR 1.7 RE 1 SL%v (IAC): ICS system '%v' has minimum password length of %v. Minimum 12 characters required at Security Level 2+.",
        [input.target_sl, system.name, system.password_min_length]
    )
}

violations contains msg if {
    some system in input.ics_systems
    not system.password_complexity
    msg := sprintf(
        "IEC 62443 SR 1.7 (IAC): ICS system '%v' does not enforce password complexity. Passwords must include uppercase, lowercase, digits, and special characters.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 1.8 — Public key infrastructure (PKI) certificates
# Validate PKI certificates used for authentication.
# ---------------------------------------------------------------------------

violations contains msg if {
    input.target_sl >= 3
    not input.authentication.pki_or_certificate_based
    msg := sprintf(
        "IEC 62443 SR 1.8 SL%v (IAC): PKI/certificate-based authentication is not implemented. Required at Security Level 3+ for strong identity assurance.",
        [input.target_sl]
    )
}

violations contains msg if {
    input.authentication.pki_or_certificate_based
    not input.authentication.certificate_revocation_checking
    msg := "IEC 62443 SR 1.8 (IAC): Certificate revocation checking (CRL/OCSP) is not implemented. Revoked certificates must be detected and rejected."
}

# ---------------------------------------------------------------------------
# SR 1.9 — Strength of public key authentication
# Enforce cryptographic algorithm and key length requirements.
# ---------------------------------------------------------------------------

violations contains msg if {
    input.authentication.pki_or_certificate_based
    not input.authentication.strong_cryptography
    msg := "IEC 62443 SR 1.9 (IAC): Public key authentication uses weak cryptographic algorithms. Use RSA 2048+, ECDSA 256+, or equivalent strength algorithms."
}

# ---------------------------------------------------------------------------
# SR 1.10 — Authenticator feedback
# Obscure authentication feedback (e.g., mask passwords during entry).
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    system.authenticator_feedback_obscured == false
    msg := sprintf(
        "IEC 62443 SR 1.10 (IAC): ICS system '%v' displays authenticator feedback in plaintext. Authentication information (passwords, tokens) must be obscured during entry.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 1.11 — Unsuccessful login attempts
# Enforce lockout after a defined number of failed authentication attempts.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    system.account_lockout_threshold > 10
    msg := sprintf(
        "IEC 62443 SR 1.11 (IAC): ICS system '%v' allows %v failed login attempts before lockout. Threshold must be 10 or fewer.",
        [system.name, system.account_lockout_threshold]
    )
}

violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    system.account_lockout_threshold > 5
    msg := sprintf(
        "IEC 62443 SR 1.11 RE 1 SL%v (IAC): ICS system '%v' allows %v failed login attempts. Threshold must be 5 or fewer at Security Level 2+.",
        [input.target_sl, system.name, system.account_lockout_threshold]
    )
}

violations contains msg if {
    some system in input.ics_systems
    not system.account_lockout_enabled
    msg := sprintf(
        "IEC 62443 SR 1.11 (IAC): ICS system '%v' has no account lockout policy. Account lockout after failed attempts is required.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 1.12 — System use notification
# Display a warning banner before authentication.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.system_use_notification
    msg := sprintf(
        "IEC 62443 SR 1.12 (IAC): ICS system '%v' does not display a system use notification. A warning banner indicating authorized use only must be displayed before login.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 1.13 — Access via untrusted networks
# Authenticate and monitor access via untrusted networks (e.g., Internet, WiFi).
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    system.remote_access_enabled
    not system.remote_access_controlled
    msg := sprintf(
        "IEC 62443 SR 1.13 (IAC): ICS system '%v' has uncontrolled remote access. Remote access via untrusted networks must use VPN, jump host, or equivalent controls.",
        [system.name]
    )
}

violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    system.remote_access_enabled
    not system.remote_access_mfa
    msg := sprintf(
        "IEC 62443 SR 1.13 RE 1 SL%v (IAC): ICS system '%v' remote access does not enforce MFA. Multi-factor authentication is required for all remote IACS access at SL 2+.",
        [input.target_sl, system.name]
    )
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

compliant if { count(violations) == 0 }

fr1_passing_srs := count([sr |
    sr := [
        count([v | some v in violations; contains(v, "SR 1.1")]) == 0,
        count([v | some v in violations; contains(v, "SR 1.2")]) == 0,
        count([v | some v in violations; contains(v, "SR 1.3")]) == 0,
        count([v | some v in violations; contains(v, "SR 1.4")]) == 0,
        count([v | some v in violations; contains(v, "SR 1.5")]) == 0,
        count([v | some v in violations; contains(v, "SR 1.6")]) == 0,
        count([v | some v in violations; contains(v, "SR 1.7")]) == 0,
        count([v | some v in violations; contains(v, "SR 1.8")]) == 0,
        count([v | some v in violations; contains(v, "SR 1.9")]) == 0,
        count([v | some v in violations; contains(v, "SR 1.10")]) == 0,
        count([v | some v in violations; contains(v, "SR 1.11")]) == 0,
        count([v | some v in violations; contains(v, "SR 1.12")]) == 0,
        count([v | some v in violations; contains(v, "SR 1.13")]) == 0,
    ][_]
    sr == true
])

compliance_report := {
    "foundational_requirement": "FR 1",
    "title":                    "Identification and Authentication Control (IAC)",
    "standard":                 "IEC 62443-3-3",
    "target_sl":                input.target_sl,
    "total_srs":                13,
    "passing_srs":              fr1_passing_srs,
    "compliant":                compliant,
    "violations":               violations,
}
