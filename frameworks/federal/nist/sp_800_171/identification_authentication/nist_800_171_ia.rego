# METADATA
# title: "NIST SP 800-171 Rev 3 - Identification and Authentication (IA) Requirements"
# custom:
#   class: compliance
#   framework: nist_sp_800_171
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 19
#     cited: 7
#     expected: 7
#     found: 19
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_171.identification_authentication

import rego.v1

# NIST SP 800-171 Rev 3 - Identification and Authentication (IA) Requirements
#
# Ids are NIST SP 800-171 Rev 3 element identifiers from the NIST CPRT export
# (https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all, sha256 19d18ef88700e468..., retrieved 2026-10-13).
# The fact checks below were written against the Rev 2 statements; each is re-keyed to the Rev 3
# requirement that carries its Rev 2 slot. A Rev 2 slot withdrawn in Rev 3 with "Incorporated into"
# is keyed to the incorporating requirement(s); one withdrawn as "Addressed by", recategorized as
# NCO, technology-specific or for consistency with SP 800-53 is retired: its rule is kept for lineage
# but it emits no violation and is not a Rev 3 control. Rev 3 status per requirement (attestation
# plus these facts) is computed by nist_800_171_main.rego (package nist_800_171.main).
# Family: 03.05 Identification and Authentication — Protecting Controlled Unclassified Information (CUI)

# 03.05.01 User Identification and Authentication (Rev 2 3.5.1): Identify system users, processes acting on behalf of users, and devices
default system_identification := false

system_identification if {
	input.nist_800_171.identification_authentication.identification.users_identified == true
	input.nist_800_171.identification_authentication.identification.processes_identified == true
	input.nist_800_171.identification_authentication.identification.devices_identified == true
}

# 03.05.02 Device Identification and Authentication (Rev 2 3.5.2): Authenticate (or verify) the identities of users, processes, or devices before
#         allowing access to organizational systems
default identity_authentication := false

identity_authentication if {
	input.nist_800_171.identification_authentication.authentication.required_before_access == true
	input.nist_800_171.identification_authentication.authentication.all_entry_points_covered == true
	input.nist_800_171.identification_authentication.authentication.mechanism_documented == true
}

# 03.05.03 Multi-Factor Authentication (Rev 2 3.5.3): Use multifactor authentication for local and network access to privileged accounts
#         and for network access to non-privileged accounts
default multifactor_authentication := false

multifactor_authentication if {
	input.nist_800_171.identification_authentication.mfa.privileged_local_mfa == true
	input.nist_800_171.identification_authentication.mfa.privileged_network_mfa == true
	input.nist_800_171.identification_authentication.mfa.non_privileged_network_mfa == true
}

# 03.05.04 Replay-Resistant Authentication (Rev 2 3.5.4): Employ replay-resistant authentication mechanisms for network access to privileged
#         and non-privileged accounts
default replay_resistant_authentication := false

replay_resistant_authentication if {
	input.nist_800_171.identification_authentication.replay_resistant.mechanism_implemented == true
	input.nist_800_171.identification_authentication.replay_resistant.covers_privileged == true
	input.nist_800_171.identification_authentication.replay_resistant.covers_non_privileged == true
}

# 03.05.05 Identifier Management (Rev 2 3.5.5): Employ identifier management including disabling identifiers after 35 days of inactivity
default identifier_management := false

identifier_management if {
	input.nist_800_171.identification_authentication.identifier_mgmt.inactivity_period_days <= 35
	input.nist_800_171.identification_authentication.identifier_mgmt.disable_on_inactivity == true
	input.nist_800_171.identification_authentication.identifier_mgmt.unique_identifiers == true
}

# RETIRED, not a Rev 3 control (Rev 2 3.5.6, withdrawn in Rev 3: Consistency with SP 800-53.): Disable identifiers after a defined inactivity period
default identifier_inactivity_disable := false

identifier_inactivity_disable if {
	input.nist_800_171.identification_authentication.inactivity_disable.policy_defined == true
	input.nist_800_171.identification_authentication.inactivity_disable.automated_enforcement == true
	input.nist_800_171.identification_authentication.inactivity_disable.period_documented == true
}

# 03.05.07 Password Management (Rev 2 3.5.7): Enforce a minimum password complexity and change requirements for passwords
default password_complexity := false

password_complexity if {
	input.nist_800_171.identification_authentication.password_complexity.minimum_length >= 12
	input.nist_800_171.identification_authentication.password_complexity.complexity_enforced == true
	input.nist_800_171.identification_authentication.password_complexity.change_requirements_defined == true
}

# RETIRED, not a Rev 3 control (Rev 2 3.5.8, withdrawn in Rev 3: Consistency with SP 800-53.): Prohibit password reuse for a specified number of generations (minimum 5)
default password_reuse_prohibited := false

password_reuse_prohibited if {
	input.nist_800_171.identification_authentication.password_reuse.generations_remembered >= 5
	input.nist_800_171.identification_authentication.password_reuse.enforcement_automated == true
}

# RETIRED, not a Rev 3 control (Rev 2 3.5.9, withdrawn in Rev 3: Consistency with SP 800-53.): Allow temporary password use with an immediate change requirement
default temporary_password_control := false

temporary_password_control if {
	input.nist_800_171.identification_authentication.temp_password.immediate_change_required == true
	input.nist_800_171.identification_authentication.temp_password.secure_delivery == true
	input.nist_800_171.identification_authentication.temp_password.expiry_enforced == true
}

# 03.05.07 (Rev 2 3.5.10, withdrawn in Rev 3: Incorporated into 03.05.07.): Store and transmit only cryptographically-protected passwords
default password_cryptographic_protection := false

password_cryptographic_protection if {
	input.nist_800_171.identification_authentication.password_crypto.storage_hashed == true
	input.nist_800_171.identification_authentication.password_crypto.transmission_encrypted == true
	input.nist_800_171.identification_authentication.password_crypto.approved_algorithms == true
}

# 03.05.11 Authentication Feedback (Rev 2 3.5.11): Obscure feedback of authentication information during the authentication process
default authentication_feedback_obscured := false

authentication_feedback_obscured if {
	input.nist_800_171.identification_authentication.feedback.password_masked == true
	input.nist_800_171.identification_authentication.feedback.no_hint_displayed == true
	input.nist_800_171.identification_authentication.feedback.all_interfaces_covered == true
}

# Violations set
violations contains msg if {
	not system_identification
	msg := "NIST SP 800-171 03.05.01: All system users, processes, and devices must be uniquely identified"
}

violations contains msg if {
	not identity_authentication
	msg := "NIST SP 800-171 03.05.02: Identity must be authenticated before granting access to organizational systems at all entry points"
}

violations contains msg if {
	not multifactor_authentication
	msg := "NIST SP 800-171 03.05.03: MFA must be used for local and network access to privileged accounts and network access to non-privileged accounts"
}

violations contains msg if {
	not replay_resistant_authentication
	msg := "NIST SP 800-171 03.05.04: Replay-resistant authentication mechanisms must be employed for network access to all account types"
}

violations contains msg if {
	not identifier_management
	msg := "NIST SP 800-171 03.05.05: Identifiers must be managed with unique IDs and disabled after a maximum of 35 days of inactivity"
}

violations contains msg if {
	not password_complexity
	msg := "NIST SP 800-171 03.05.07: Password complexity must be enforced including minimum length of 12 characters and defined change requirements"
}

violations contains msg if {
	not password_cryptographic_protection
	msg := "NIST SP 800-171 03.05.07 (Rev 2 3.5.10, withdrawn in Rev 3: Incorporated into 03.05.07.): Passwords must be cryptographically hashed for storage and encrypted for transmission using approved algorithms"
}

violations contains msg if {
	not authentication_feedback_obscured
	msg := "NIST SP 800-171 03.05.11: Authentication feedback (passwords) must be obscured on all interfaces during the authentication process"
}

# Compliance aggregation
default compliant := false

compliant if count(violations) == 0

compliance_report := {
	"family": "03.05 Identification and Authentication",
	"standard": "NIST SP 800-171 Rev 3",
	"total_controls": 7,
	"violations": violations,
	"compliant": compliant,
	"retired_rev2_checks": {
		"rev2_3.5.6_identifier_inactivity_disable": identifier_inactivity_disable,
		"rev2_3.5.8_password_reuse_prohibited": password_reuse_prohibited,
		"rev2_3.5.9_temporary_password_control": temporary_password_control,
	},
	"controls": {
		"03.05.01_system_identification": system_identification,
		"03.05.02_identity_authentication": identity_authentication,
		"03.05.03_multifactor_authentication": multifactor_authentication,
		"03.05.04_replay_resistant_authentication": replay_resistant_authentication,
		"03.05.05_identifier_management": identifier_management,
		"03.05.07_password_complexity": password_complexity,
		"03.05.07_password_cryptographic_protection": password_cryptographic_protection,
		"03.05.11_authentication_feedback_obscured": authentication_feedback_obscured,
	},
}
