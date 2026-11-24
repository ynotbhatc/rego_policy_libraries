# METADATA
# title: "IEC 62443-3-3 FR 1 — Identification and Authentication Control (IAC)"
# custom:
#   class: ot
#   framework: iec_62443
#   source: iec
#   domains: [ot, industrial]
#   coverage:
#     checks: 38
#     cited: 14
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package iec_62443.fr1

import rego.v1

# =============================================================================
# IEC 62443-3-3:2013 FR 1 — Identification and Authentication Control (IAC)
#
# Edition: IEC 62443-3-3:2013 (edition 1.0, System security requirements and
# security levels). SR and RE numbers below are that edition's.
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

# A missing value fails closed: absent password length/lockout/feedback is a violation.
min_value_at_least(system, key, n) if {
	is_number(system[key])
	system[key] >= n
}

# Lockout must be enabled (> 0) and no more than n failed attempts.
lockout_within(system, n) if {
	is_number(system.account_lockout_threshold)
	system.account_lockout_threshold > 0
	system.account_lockout_threshold <= n
}

# SL-dependent requirements (SR x RE y) are gated on target_sl. Without it they
# silently never run, so its absence is itself a violation.
violations contains "IEC 62443 FR 1 (IAC): evidence missing - input.target_sl not provided; Security Level dependent requirements cannot be evaluated" if {
	not is_number(object.get(input, "target_sl", null))
}

# ---------------------------------------------------------------------------
# SR 1.1 — Human user identification and authentication
# All human users must be uniquely identified and authenticated before access.
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	not system.unique_identification == true
	finding := sprintf(
		"IEC 62443 SR 1.1 (IAC): ICS system '%v' does not enforce unique user identification. Every human user must have a unique identifier.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "unique_identification")])
}

# SR 1.1 RE 1 (SL 2+): Multi-factor authentication for all interfaces
violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	some system in input.ics_systems
	not system.mfa_enabled == true
	finding := sprintf(
		"IEC 62443 SR 1.1 RE 1 SL%v (IAC): ICS system '%v' does not enforce multi-factor authentication. MFA is required at Security Level 2+.",
		[input.target_sl, system.name],
	)
	msg := concat("", [finding, _ev_item(system, "mfa_enabled")])
}

# SR 1.1 RE 2 (SL 3+): Hardware token-based authentication
violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 3
	not input.authentication.hardware_token_authentication == true
	finding := sprintf(
		"IEC 62443 SR 1.1 RE 2 SL%v (IAC): Hardware token-based authentication is not implemented. Required at Security Level 3+.",
		[input.target_sl],
	)
	msg := concat("", [finding, _ev_input("authentication.hardware_token_authentication")])
}

# ---------------------------------------------------------------------------
# SR 1.2 — Software process and device identification and authentication
# Software processes and devices must be identified and authenticated.
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	not system.device_authentication == true
	finding := sprintf(
		"IEC 62443 SR 1.2 (IAC): ICS system '%v' does not authenticate software processes or devices. Device-to-device authentication is required.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "device_authentication")])
}

# SR 1.2 RE 1 (SL 2+): Unique identification for all devices
violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	some system in input.ics_systems
	not system.device_unique_id == true
	finding := sprintf(
		"IEC 62443 SR 1.2 RE 1 SL%v (IAC): ICS system '%v' devices do not have unique identifiers. All IACS devices must have unique IDs at SL 2+.",
		[input.target_sl, system.name],
	)
	msg := concat("", [finding, _ev_item(system, "device_unique_id")])
}

# ---------------------------------------------------------------------------
# SR 1.3 — Account management
# Manage accounts for human users, software processes, and devices.
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.authentication.centralized_identity_management == true
	finding := "IEC 62443 SR 1.3 (IAC): No centralized account management. IACS accounts must be centrally managed, reviewed, and deprovisioned promptly."
	msg := concat("", [finding, _ev_input("authentication.centralized_identity_management")])
}

violations contains msg if {
	some system in input.ics_systems
	not system.account_review_process == true
	finding := sprintf(
		"IEC 62443 SR 1.3 (IAC): ICS system '%v' has no periodic account review process. Accounts must be reviewed regularly for continued business need.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "account_review_process")])
}

# SR 1.3 RE 1 (SL 2+): Unified account management policy
violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	not input.authentication.unified_account_policy == true
	finding := sprintf(
		"IEC 62443 SR 1.3 RE 1 SL%v (IAC): No unified account management policy across all IACS components. Required at Security Level 2+.",
		[input.target_sl],
	)
	msg := concat("", [finding, _ev_input("authentication.unified_account_policy")])
}

# ---------------------------------------------------------------------------
# SR 1.4 — Identifier management
# Manage identifiers by uniqueness, re-use prevention, and revocation.
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	system.default_credentials_unchanged == true
	msg := sprintf(
		"IEC 62443 SR 1.4 (IAC): ICS system '%v' uses unchanged default credentials. Default identifiers are a critical vulnerability — change all defaults before deployment.",
		[system.name],
	)
}

violations contains msg if {
	not input.authentication.identifier_reuse_prevented == true
	finding := "IEC 62443 SR 1.4 (IAC): IACS does not prevent identifier reuse for a defined period. Deactivated identifiers must not be reassigned for at least 90 days."
	msg := concat("", [finding, _ev_input("authentication.identifier_reuse_prevented")])
}

# ---------------------------------------------------------------------------
# SR 1.5 — Authenticator management
# Manage authenticators (passwords, tokens, keys) through their lifecycle.
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	not system.authenticator_lifecycle_managed == true
	finding := sprintf(
		"IEC 62443 SR 1.5 (IAC): ICS system '%v' has no authenticator lifecycle management. Passwords, keys, and tokens must have defined issuance, rotation, and revocation policies.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "authenticator_lifecycle_managed")])
}

violations contains msg if {
	not input.authentication.initial_authenticator_secure_distribution == true
	finding := "IEC 62443 SR 1.5 (IAC): Authenticators are not distributed via secure channels. Initial credentials must be delivered through a secure out-of-band mechanism."
	msg := concat("", [finding, _ev_input("authentication.initial_authenticator_secure_distribution")])
}

# ---------------------------------------------------------------------------
# SR 1.6 — Wireless access management
# Authenticate wireless connections to the IACS.
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	system.wireless_access == true
	not system.wireless_encrypted == true
	finding := sprintf(
		"IEC 62443 SR 1.6 (IAC): ICS system '%v' has unencrypted wireless access. All wireless connections to IACS must use strong authentication and encryption.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "wireless_encrypted")])
}

violations contains msg if {
	some system in input.ics_systems
	system.wireless_access == true
	not system.wireless_authentication == true
	finding := sprintf(
		"IEC 62443 SR 1.6 (IAC): ICS system '%v' wireless access lacks authentication. Mutual authentication is required for all IACS wireless connections.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "wireless_authentication")])
}

violations contains msg if {
	not input.network.wireless_policy_documented == true
	finding := "IEC 62443 SR 1.6 (IAC): No wireless access policy for IACS. A documented policy defining allowed wireless use is required."
	msg := concat("", [finding, _ev_input("network.wireless_policy_documented")])
}

# ---------------------------------------------------------------------------
# SR 1.7 — Strength of password-based authentication
# Enforce minimum password strength requirements.
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	not min_value_at_least(system, "password_min_length", 8)
	msg := sprintf(
		"IEC 62443 SR 1.7 (IAC): ICS system '%v' has minimum password length of %v characters. Minimum 8 characters required (12+ recommended for SL 2+).",
		[system.name, object.get(system, "password_min_length", "not set")],
	)
}

violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	some system in input.ics_systems
	not min_value_at_least(system, "password_min_length", 12)
	msg := sprintf(
		"IEC 62443 SR 1.7 RE 1 SL%v (IAC): ICS system '%v' has minimum password length of %v. Minimum 12 characters required at Security Level 2+.",
		[input.target_sl, system.name, object.get(system, "password_min_length", "not set")],
	)
}

violations contains msg if {
	some system in input.ics_systems
	not system.password_complexity == true
	finding := sprintf(
		"IEC 62443 SR 1.7 (IAC): ICS system '%v' does not enforce password complexity. Passwords must include uppercase, lowercase, digits, and special characters.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "password_complexity")])
}

# ---------------------------------------------------------------------------
# SR 1.8 — Public key infrastructure (PKI) certificates
# Validate PKI certificates used for authentication.
# ---------------------------------------------------------------------------

violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 3
	not input.authentication.pki_or_certificate_based == true
	finding := sprintf(
		"IEC 62443 SR 1.8 SL%v (IAC): PKI/certificate-based authentication is not implemented. Required at Security Level 3+ for strong identity assurance.",
		[input.target_sl],
	)
	msg := concat("", [finding, _ev_input("authentication.pki_or_certificate_based")])
}

violations contains msg if {
	input.authentication.pki_or_certificate_based == true
	not input.authentication.certificate_revocation_checking == true
	finding := "IEC 62443 SR 1.8 (IAC): Certificate revocation checking (CRL/OCSP) is not implemented. Revoked certificates must be detected and rejected."
	msg := concat("", [finding, _ev_input("authentication.certificate_revocation_checking")])
}

# ---------------------------------------------------------------------------
# SR 1.9 — Strength of public key authentication
# Enforce cryptographic algorithm and key length requirements.
# ---------------------------------------------------------------------------

violations contains msg if {
	input.authentication.pki_or_certificate_based == true
	not input.authentication.strong_cryptography == true
	finding := "IEC 62443 SR 1.9 (IAC): Public key authentication uses weak cryptographic algorithms. Use RSA 2048+, ECDSA 256+, or equivalent strength algorithms."
	msg := concat("", [finding, _ev_input("authentication.strong_cryptography")])
}

# ---------------------------------------------------------------------------
# SR 1.10 — Authenticator feedback
# Obscure authentication feedback (e.g., mask passwords during entry).
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	not system.authenticator_feedback_obscured == true
	msg := sprintf(
		"IEC 62443 SR 1.10 (IAC): ICS system '%v' displays authenticator feedback in plaintext. Authentication information (passwords, tokens) must be obscured during entry.",
		[system.name],
	)
}

# ---------------------------------------------------------------------------
# SR 1.11 — Unsuccessful login attempts
# Enforce lockout after a defined number of failed authentication attempts.
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	not lockout_within(system, 10)
	msg := sprintf(
		"IEC 62443 SR 1.11 (IAC): ICS system '%v' allows %v failed login attempts before lockout. Threshold must be 10 or fewer.",
		[system.name, object.get(system, "account_lockout_threshold", "not set")],
	)
}

violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	some system in input.ics_systems
	not lockout_within(system, 5)
	msg := sprintf(
		"IEC 62443 SR 1.11 RE 1 SL%v (IAC): ICS system '%v' allows %v failed login attempts. Threshold must be 5 or fewer at Security Level 2+.",
		[input.target_sl, system.name, object.get(system, "account_lockout_threshold", "not set")],
	)
}

violations contains msg if {
	some system in input.ics_systems
	not system.account_lockout_enabled == true
	finding := sprintf(
		"IEC 62443 SR 1.11 (IAC): ICS system '%v' has no account lockout policy. Account lockout after failed attempts is required.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "account_lockout_enabled")])
}

# ---------------------------------------------------------------------------
# SR 1.12 — System use notification
# Display a warning banner before authentication.
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	not system.system_use_notification == true
	finding := sprintf(
		"IEC 62443 SR 1.12 (IAC): ICS system '%v' does not display a system use notification. A warning banner indicating authorized use only must be displayed before login.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "system_use_notification")])
}

# ---------------------------------------------------------------------------
# SR 1.13 — Access via untrusted networks
# Authenticate and monitor access via untrusted networks (e.g., Internet, WiFi).
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	system.remote_access_enabled == true
	not system.remote_access_controlled == true
	finding := sprintf(
		"IEC 62443 SR 1.13 (IAC): ICS system '%v' has uncontrolled remote access. Remote access via untrusted networks must use VPN, jump host, or equivalent controls.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "remote_access_controlled")])
}

violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	some system in input.ics_systems
	system.remote_access_enabled == true
	not system.remote_access_mfa == true
	finding := sprintf(
		"IEC 62443 SR 1.13 RE 1 SL%v (IAC): ICS system '%v' remote access does not enforce MFA. Multi-factor authentication is required for all remote IACS access at SL 2+.",
		[input.target_sl, system.name],
	)
	msg := concat("", [finding, _ev_item(system, "remote_access_mfa")])
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Evidence missing: a requirement with no evidence cannot be reported as passing
# (semantic review 2026-11-13)
# ---------------------------------------------------------------------------

violations contains "IEC 62443 SR 1.1 (IAC): evidence missing — input.ics_systems not collected, so this requirement cannot be verified" if {
	count(object.get(input, "ics_systems", [])) == 0
}

violations contains "IEC 62443 SR 1.2 (IAC): evidence missing — input.ics_systems not collected, so this requirement cannot be verified" if {
	count(object.get(input, "ics_systems", [])) == 0
}

violations contains "IEC 62443 SR 1.7 (IAC): evidence missing — input.ics_systems not collected, so this requirement cannot be verified" if {
	count(object.get(input, "ics_systems", [])) == 0
}

violations contains "IEC 62443 SR 1.10 (IAC): evidence missing — input.ics_systems not collected, so this requirement cannot be verified" if {
	count(object.get(input, "ics_systems", [])) == 0
}

violations contains "IEC 62443 SR 1.11 (IAC): evidence missing — input.ics_systems not collected, so this requirement cannot be verified" if {
	count(object.get(input, "ics_systems", [])) == 0
}

violations contains "IEC 62443 SR 1.12 (IAC): evidence missing — input.ics_systems not collected, so this requirement cannot be verified" if {
	count(object.get(input, "ics_systems", [])) == 0
}

violations contains "IEC 62443 SR 1.13 (IAC): evidence missing — input.ics_systems not collected, so this requirement cannot be verified" if {
	count(object.get(input, "ics_systems", [])) == 0
}

violations contains "IEC 62443 SR 1.8 (IAC): evidence missing — input.authentication not collected, so this requirement cannot be verified" if {
	not input.authentication
}

violations contains "IEC 62443 SR 1.9 (IAC): evidence missing — input.authentication not collected, so this requirement cannot be verified" if {
	not input.authentication
}

compliant if count(violations) == 0

fr1_passing_srs := count([sr |
	sr := [
		count([v | some v in violations; contains(v, "SR 1.1 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 1.2 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 1.3 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 1.4 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 1.5 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 1.6 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 1.7 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 1.8 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 1.9 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 1.10 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 1.11 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 1.12 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 1.13 ")]) == 0,
	][_]
	sr == true
])

compliance_report := {
	"foundational_requirement": "FR 1",
	"title": "Identification and Authentication Control (IAC)",
	"standard": "IEC 62443-3-3",
	"target_sl": object.get(input, ["target_sl"], 0),
	"total_srs": 13,
	"passing_srs": fr1_passing_srs,
	"compliant": compliant,
	"violations": violations,
}

# ---------------------------------------------------------------------------
# Facts that decide whether a requirement applies, or that fail it when true,
# must be stated as booleans. "Does not apply" is the boolean false; an absent
# fact, null or a string such as "false" is an evidence problem and a finding.
# Rows: [fact, requirement, lowest target SL at which the fact is read].
# ---------------------------------------------------------------------------

_stated_system_facts := [
	["default_credentials_unchanged", "SR 1.4", 1],
	["wireless_access", "SR 1.6", 1],
	["remote_access_enabled", "SR 1.13", 1],
]

_sl_at_least(n) if n <= 1

_sl_at_least(n) if {
	is_number(input.target_sl)
	input.target_sl >= n
}

violations contains msg if {
	some [fact, requirement, min_sl] in _stated_system_facts
	_sl_at_least(min_sl)
	some system in input.ics_systems
	not is_boolean(object.get(system, fact, null))
	msg := sprintf(
		"IEC 62443 %s (IAC): ICS system '%v' does not state %s as true or false, so the requirement cannot be decided.%s",
		[requirement, object.get(system, "name", "<unnamed>"), fact, _ev_item(system, fact)],
	)
}

# ---------------------------------------------------------------------------
# Evidence rule: only the boolean true passes a yes/no fact. A fact that is
# absent, null or not a boolean fails its check, and the finding names the
# evidence problem.
# ---------------------------------------------------------------------------

default _facts := {}

_facts := input

_evidence_note(value, name) := "" if {
	is_boolean(value)
} else := sprintf(" (evidence missing: %s not collected)", [name]) if {
	value == null
} else := sprintf(" (evidence invalid: %s is not a boolean, got %s)", [name, type_name(value)])

_ev_input(path) := _evidence_note(object.get(_facts, split(path, "."), null), concat(".", ["input", path]))

_ev_item(item, path) := _evidence_note(object.get(item, split(path, "."), null), path) if {
	is_object(item)
} else := sprintf(" (evidence invalid: item is not an object, got %s; %s not collected)", [type_name(item), path])
