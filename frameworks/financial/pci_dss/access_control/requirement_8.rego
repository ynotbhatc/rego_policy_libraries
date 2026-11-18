# PCI DSS v4.0.1 Requirement 8 - Identify Users and Authenticate Access to System Components

# METADATA
# title: "PCI DSS v4.0.1 Requirement 8 - Identify Users and Authenticate Access to System Components"
# custom:
#   class: compliance
#   framework: pci_dss
#   source: pci-ssc
#   domains: [financial, payment-cards]
#   coverage:
#     checks: 16
#     cited: 5
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package pci_dss.access_control.requirement_8

import rego.v1

# Parameter values below were checked on 2026-11-17 against PCI SSC's own public material: the
# Self-Assessment Questionnaire D for Service Providers (v4.0, listings.pcisecuritystandards.org), whose
# requirement rows carry the parameters (8.2.6 90 days, 8.2.8 15 minutes, 8.3.4 not more than 10 attempts
# and 30 minutes or until identity confirmed, 8.3.6 12 characters or 8 where the system cannot support 12,
# 8.3.7 last four, 8.3.9 90 days or dynamic analysis), PCI SSC FAQ 1590 (8.3.9 applies only where a
# password/passphrase is the only factor) and FAQ 1593 (8.3.10 superseded by 8.3.10.1 after 31 March 2025).
# The standard's text is licensed and is not reproduced here; ids and parameter values are facts.

# Numbers are checked as numbers: OPA orders every string above every number, so `"5" >= 12` is true.
_num_le(x, n) if {
	is_number(x)
	x <= n
}

_num_ge(x, n) if {
	is_number(x)
	x >= n
}

# =================================================================
# 8.1 - Processes and mechanisms for user identification/authentication
# =================================================================

# x.1.1: documented, kept up to date (current), in use (approved). No annual review is part of x.1.1; the
# annual review is 12.1.2 for the information security policy (audit 2026-11-17 follow-up).
authentication_policies_established if {
	input.pci.authentication.policies.documented == true
	input.pci.authentication.policies.approved == true
	input.pci.authentication.policies.current == true
}

authentication_roles_defined if {
	input.pci.authentication.roles.defined == true
	input.pci.authentication.responsibilities.assigned == true
}

# =================================================================
# 8.2 - User identification and related accounts managed throughout lifecycle
# =================================================================

# 8.2.1 unique IDs; 8.2.2 group, shared or generic accounts are not banned outright: they may be used on an
# exception basis when managed (prevented unless needed, time-limited, justified, approved, identity
# confirmed, attributable). Either the prohibition or the managed-exception evidence satisfies 8.2.2.
_shared_generic_group_ok if {
	input.pci.user_ids.shared_accounts.prohibited == true
	input.pci.user_ids.generic_accounts.prohibited_in_cde == true
	input.pci.user_ids.group_accounts.prohibited == true
}

_shared_generic_group_ok if input.pci.user_ids.shared_generic_group.exception_basis_managed == true

unique_user_ids if {
	input.pci.user_ids.unique_per_user == true
	_shared_generic_group_ok
}

# 8.2.4 add/delete/modify approved, 8.2.5 terminated users revoked immediately, 8.2.6 inactive accounts
# removed or disabled within 90 days of inactivity.
account_lifecycle_managed if {
	input.pci.account_lifecycle.provisioning.approval_required == true
	input.pci.account_lifecycle.modification.approval_required == true
	input.pci.account_lifecycle.termination.immediate_revocation == true
	input.pci.account_lifecycle.inactive_accounts.disabled_after_90_days == true
}

# 8.2.7 third-party remote-access accounts: enabled only when needed, disabled when not in use, monitored.
vendor_accounts_managed if {
	input.pci.vendor_accounts.disabled_when_not_in_use == true
	input.pci.vendor_accounts.monitored_when_active == true
	input.pci.vendor_accounts.time_limited == true
}

# 8.2.8 idle sessions: re-authentication after no more than 15 minutes idle (a timeout of 0 usually means
# "never", so it does not pass).
idle_session_reauthentication if {
	_num_ge(input.pci.sessions.idle_timeout_minutes, 1)
	_num_le(input.pci.sessions.idle_timeout_minutes, 15)
	input.pci.sessions.reauthentication_required == true
}

# =================================================================
# 8.3 - User authentication factors managed for all users
# =================================================================

# 8.3.6 minimum length 12, or 8 where the system does not support 12 (that limitation must be declared:
# an absent flag does not open the 8-character path).
_minimum_length_ok if _num_ge(input.pci.passwords.minimum_length, 12)

_minimum_length_ok if {
	_num_ge(input.pci.passwords.minimum_length, 8)
	input.pci.passwords.system_supports_12_characters == false
}

# 8.3.4 lockout after not more than 10 invalid attempts (a threshold of 0 means "never lock" and fails),
# for at least 30 minutes or until the user's identity is confirmed.
_lockout_ok if {
	_num_ge(input.pci.passwords.lockout.after_attempts, 1)
	_num_le(input.pci.passwords.lockout.after_attempts, 10)
	_lockout_duration_ok
}

_lockout_duration_ok if _num_ge(input.pci.passwords.lockout.duration_minutes, 30)

_lockout_duration_ok if input.pci.passwords.lockout.until_identity_confirmed == true

# Password/passphrase parameters: 8.3.4 lockout, 8.3.6 length and numeric + alphabetic content,
# 8.3.7 not any of the last four. (complexity.required and no_dictionary_words are not 8.3.6 parameters
# and no longer gate this control; the password lifetime is 8.3.9, evaluated separately below.)
password_requirements if {
	_minimum_length_ok
	input.pci.passwords.numeric_and_alpha.required == true
	_num_ge(input.pci.passwords.history.count, 4)
	_lockout_ok
}

# 8.3.9 applies only where passwords/passphrases are the ONLY authentication factor for user access on an
# in-scope component (FAQ 1590; FAQ 1591: a password-only hop inside the CDE still counts). Then either a
# change at least every 90 days or dynamic analysis of account security posture satisfies it.
#   input.pci.passwords.single_factor_only == false  -> not applicable (MFA everywhere), passes
#   single_factor_only == true                        -> max_age_days <= 90 OR dynamic_posture_analysis
#   single_factor_only absent                         -> passes only on evidence that meets 8.3.9 in
#                                                        every case (a change at least every 90 days);
#                                                        otherwise fails closed
_password_lifetime_met if {
	_num_ge(input.pci.passwords.max_age_days, 1)
	_num_le(input.pci.passwords.max_age_days, 90)
}

_password_lifetime_met if input.pci.passwords.dynamic_posture_analysis.implemented == true

single_factor_password_lifetime if input.pci.passwords.single_factor_only == false

single_factor_password_lifetime if {
	input.pci.passwords.single_factor_only == true
	_password_lifetime_met
}

single_factor_password_lifetime if {
	not is_boolean(object.get(input, ["pci", "passwords", "single_factor_only"], null))
	_num_ge(input.pci.passwords.max_age_days, 1)
	_num_le(input.pci.passwords.max_age_days, 90)
}

# 8.3.10.1 (service providers only; future-dated in v4.0, in force since 31 March 2025, superseding 8.3.10 per
# FAQ 1593): where passwords are the only factor for CUSTOMER user access, a change at least every 90 days or
# dynamic posture analysis. Not applicable to merchants or to consumer users accessing their own card data.
#   input.pci.entity.service_provider == false                 -> not applicable, passes
#   input.pci.passwords.customer_accounts.single_factor_only    -> false: not applicable; true: 90 days or
#                                                                  dynamic analysis; absent: only 90-day
#                                                                  evidence passes, otherwise fails closed
_cust := object.get(input, ["pci", "passwords", "customer_accounts"], {})

_customer_rotation_90 if {
	_num_ge(_cust.max_age_days, 1)
	_num_le(_cust.max_age_days, 90)
}

service_provider_customer_password_lifetime if input.pci.entity.service_provider == false

service_provider_customer_password_lifetime if {
	input.pci.entity.service_provider == true
	_cust.single_factor_only == false
}

service_provider_customer_password_lifetime if {
	input.pci.entity.service_provider == true
	_cust.single_factor_only == true
	_customer_rotation_90
}

service_provider_customer_password_lifetime if {
	input.pci.entity.service_provider == true
	_cust.single_factor_only == true
	_cust.dynamic_posture_analysis.implemented == true
}

service_provider_customer_password_lifetime if {
	input.pci.entity.service_provider == true
	not is_boolean(object.get(_cust, "single_factor_only", null))
	_customer_rotation_90
}

# 8.3.5 first-time and reset values are unique and changed immediately after first use.
first_use_password_change if {
	input.pci.passwords.first_use.change_required == true
	input.pci.passwords.reset.immediate_change_required == true
	input.pci.passwords.temporary.single_use == true
}

# 8.3.2 strong cryptography renders factors unreadable in transmission and storage; 8.2.3 (service
# providers only) unique factors per customer premises. On-screen masking is not a v4.0.1 parameter and no
# longer gates this control.
_service_provider_factors_ok if input.pci.auth_factors.service_providers.different_from_customers == true

_service_provider_factors_ok if input.pci.entity.service_provider == false

authentication_factors_protected if {
	input.pci.auth_factors.stored.encrypted == true
	input.pci.auth_factors.transmission.encrypted == true
	_service_provider_factors_ok
}

# =================================================================
# 8.4 - Multi-factor authentication (MFA) implemented
# =================================================================

# 8.4.1 MFA for all non-console administrative access into the CDE
mfa_for_cde_admin if {
	input.pci.mfa.cde_admin_access.required == true
	input.pci.mfa.non_console_admin.required == true
	input.pci.mfa.factors.at_least_two == true
	input.pci.mfa.factors.different_categories == true
}

# 8.4.3 MFA for all remote network access from outside the entity's network that could access or impact
# the CDE. A remote-access path the entity does not use (VPN, remote desktop) is declared in_use false.
_remote_path_ok(p) if p.mfa_enforced == true

_remote_path_ok(p) if p.in_use == false

mfa_for_remote_access if {
	input.pci.mfa.remote_access.required == true
	_remote_path_ok(object.get(input, ["pci", "mfa", "vpn"], {}))
	_remote_path_ok(object.get(input, ["pci", "mfa", "remote_desktop"], {}))
}

# 8.4.2 MFA for all access into the CDE (future-dated in v4.0, in force since 31 March 2025)
mfa_for_all_cde_access if {
	input.pci.mfa.all_cde_access.required == true
	input.pci.mfa.user_cde_access.enforced == true
}

# 8.5.1 MFA system configuration: not susceptible to replay, not bypassable, two different factor types
mfa_system_secure if {
	input.pci.mfa.replay_attacks.prevented == true
	input.pci.mfa.bypass.not_possible_by_any_single_admin == true
	input.pci.mfa.factors.cannot_be_same_type == true
}

# =================================================================
# 8.5 - Multi-factor authentication systems configured to prevent misuse
# =================================================================

# 8.5.1 success of all authentication factors is required before access is granted. (The former checks -
# time-based OTP, single-use OTP and push number matching - are implementation choices the standard does
# not require; a FIDO2 deployment has none of them.)
mfa_not_susceptible_to_replay if {
	input.pci.mfa.replay_attacks.prevented == true
	input.pci.mfa.all_factors_required == true
}

# =================================================================
# 8.6 - Use of application and system accounts managed
# =================================================================

# 8.6.2 passwords for interactive-capable system accounts not hard coded (a vault is one way to show it);
# 8.6.3 changed periodically at the frequency of the entity's targeted risk analysis (automation is one way).
_system_credentials_not_hard_coded if input.pci.system_accounts.credentials.in_vault == true

_system_credentials_not_hard_coded if input.pci.system_accounts.credentials.not_hard_coded == true

_system_credentials_rotated if input.pci.system_accounts.credentials.rotation.automated == true

_system_credentials_rotated if input.pci.system_accounts.credentials.rotation.tra_frequency_met == true

system_application_accounts if {
	input.pci.system_accounts.interactive_use.prohibited_unless_exceptional == true
	input.pci.system_accounts.authentication.managed == true
	_system_credentials_not_hard_coded
	_system_credentials_rotated
	input.pci.system_accounts.review.performed_periodically == true
}

# Every control referenced by the score, findings and roll-up has a default so a failing
# control reports false instead of making the whole score/findings undefined.
default authentication_policies_established := false

default authentication_roles_defined := false

default unique_user_ids := false

default account_lifecycle_managed := false

default vendor_accounts_managed := false

default password_requirements := false

default idle_session_reauthentication := false

default single_factor_password_lifetime := false

default service_provider_customer_password_lifetime := false

default first_use_password_change := false

default authentication_factors_protected := false

default mfa_for_cde_admin := false

default mfa_for_remote_access := false

default mfa_for_all_cde_access := false

default mfa_system_secure := false

default mfa_not_susceptible_to_replay := false

default system_application_accounts := false

default pci_requirement_8_compliant := false

# =================================================================
# Scoring
# =================================================================

pci_requirement_8_compliant if {
	authentication_policies_established
	authentication_roles_defined
	unique_user_ids
	account_lifecycle_managed
	vendor_accounts_managed
	idle_session_reauthentication
	password_requirements
	single_factor_password_lifetime
	service_provider_customer_password_lifetime
	first_use_password_change
	authentication_factors_protected
	mfa_for_cde_admin
	mfa_for_remote_access
	mfa_for_all_cde_access
	mfa_system_secure
	mfa_not_susceptible_to_replay
	system_application_accounts
}

default pci_requirement_8_score := 0

default pci_requirement_8_findings := {}

pci_requirement_8_score := score if {
	controls := [
		authentication_policies_established,
		authentication_roles_defined,
		unique_user_ids,
		account_lifecycle_managed,
		vendor_accounts_managed,
		idle_session_reauthentication,
		password_requirements,
		single_factor_password_lifetime,
		service_provider_customer_password_lifetime,
		first_use_password_change,
		authentication_factors_protected,
		mfa_for_cde_admin,
		mfa_for_remote_access,
		mfa_for_all_cde_access,
		mfa_system_secure,
		mfa_not_susceptible_to_replay,
		system_application_accounts,
	]
	passed := count([c | some c in controls; c == true])
	total := count(controls)
	score := (passed / total) * 100
}

pci_requirement_8_findings := {
	"requirement_8_1": {
		"policies_established": authentication_policies_established,
		"roles_defined": authentication_roles_defined,
	},
	"requirement_8_2": {
		"unique_user_ids": unique_user_ids,
		"account_lifecycle": account_lifecycle_managed,
		"vendor_accounts": vendor_accounts_managed,
		"idle_session_reauthentication": idle_session_reauthentication,
	},
	"requirement_8_3": {
		"password_requirements": password_requirements,
		"single_factor_password_lifetime": single_factor_password_lifetime,
		"service_provider_customer_password_lifetime_8_3_10_1": service_provider_customer_password_lifetime,
		"first_use_change": first_use_password_change,
		"factors_protected": authentication_factors_protected,
	},
	"requirement_8_4_mfa": {
		"cde_admin": mfa_for_cde_admin,
		"remote_access": mfa_for_remote_access,
		"all_cde_access": mfa_for_all_cde_access,
		"system_secure": mfa_system_secure,
		"replay_resistant": mfa_not_susceptible_to_replay,
	},
	"requirement_8_6": {"system_accounts": system_application_accounts},
	"overall_score": pci_requirement_8_score,
	"overall_compliant": pci_requirement_8_compliant,
}
