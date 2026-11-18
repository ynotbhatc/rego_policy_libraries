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

# IA-7: authentication to a cryptographic module must meet "applicable laws, executive orders, directives,
# policies, regulations, standards, and guidelines". Which standard applies is the organisation's input
# (FedRAMP's FIPS-validated-or-NSA-approved parameter is applied in the FedRAMP module, not here).
_ia7 := object.get(input, ["ia_controls", "cryptographic_module_auth"], {})

_ia7_missing contains "input.ia_controls.cryptographic_module_auth.odp.required_standards (applicable standards)" if {
	x := object.get(_ia7, ["odp", "required_standards"], null)
	not is_array(x)
}

_ia7_missing contains "input.ia_controls.cryptographic_module_auth.odp.required_standards (applicable standards)" if {
	count(object.get(_ia7, ["odp", "required_standards"], [])) == 0
}

_ia7_missing contains "input.ia_controls.cryptographic_module_auth.standards_met" if {
	not is_array(object.get(_ia7, "standards_met", null))
}

ia7_unmet contains s if {
	count(_ia7_missing) == 0
	some s in _ia7.odp.required_standards
	not s in _ia7.standards_met
}

violation contains msg if {
	count(_ia7_missing) > 0
	msg := sprintf("NIST IA-7: evidence missing — %s not collected", [concat(", ", sort(_ia7_missing))])
}

violation contains msg if {
	count(ia7_unmet) > 0
	msg := sprintf("NIST IA-7: Cryptographic module authentication does not meet the applicable standards: %v", [sort(ia7_unmet)])
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
