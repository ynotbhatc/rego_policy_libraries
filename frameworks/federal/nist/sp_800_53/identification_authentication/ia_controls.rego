# METADATA
# title: "NIST SP 800-53 Rev 5 — Identification and Authentication (IA) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 12
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
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

# IA-5(1) Password-based Authentication: passwords transmitted only over cryptographically protected
# channels and stored in a protected (approved salted key-derivation) form. One finding for the enhancement.
_ia5_1_gaps contains "transmitted only over cryptographically protected channels (input.ia_controls.authenticator_management.encrypted_in_transit)" if {
	not input.ia_controls.authenticator_management.encrypted_in_transit
}

_ia5_1_gaps contains "stored cryptographically protected (input.ia_controls.authenticator_management.encrypted_at_rest)" if {
	not input.ia_controls.authenticator_management.encrypted_at_rest
}

violation contains msg if {
	count(_ia5_1_gaps) > 0
	msg := sprintf("NIST IA-5(1): Password-based authentication — not evidenced: %s", [concat("; ", sort(_ia5_1_gaps))])
}

violation contains msg if {
	not input.ia_controls.authenticator_feedback.obscured
	msg := "NIST IA-6: Authentication feedback (e.g., password entry) is not obscured"
}

violation contains msg if {
	not input.ia_controls.cryptographic_module_auth.fips_validated
	msg := "NIST IA-7: Cryptographic module authentication not FIPS-validated"
}

violation contains msg if {
	not input.ia_controls.non_organizational_users.identified
	msg := "NIST IA-8: Non-organizational users not uniquely identified and authenticated"
}

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {"IA-1", "IA-2", "IA-2(1)", "IA-2(2)", "IA-3", "IA-4", "IA-5", "IA-5(1)", "IA-6", "IA-7", "IA-8"}

compliance_report := {
	"family": "IA",
	"name": "Identification and Authentication",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
