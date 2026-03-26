# PCI DSS v4.0 Requirement 8 - Identify Users and Authenticate Access to System Components

package pci_dss.access_control.requirement_8

import rego.v1

# =================================================================
# 8.1 - Processes and mechanisms for user identification/authentication
# =================================================================

authentication_policies_established if {
	input.pci.authentication.policies.documented == true
	input.pci.authentication.policies.approved == true
	input.pci.authentication.policies.current == true
	input.pci.authentication.policies.reviewed_annually == true
}

authentication_roles_defined if {
	input.pci.authentication.roles.defined == true
	input.pci.authentication.responsibilities.assigned == true
}

# =================================================================
# 8.2 - User identification and related accounts managed throughout lifecycle
# =================================================================

# Unique IDs assigned to all users
unique_user_ids if {
	input.pci.user_ids.unique_per_user == true
	input.pci.user_ids.shared_accounts.prohibited == true
	input.pci.user_ids.generic_accounts.prohibited_in_cde == true
	input.pci.user_ids.group_accounts.prohibited == true
}

# User account lifecycle management
account_lifecycle_managed if {
	input.pci.account_lifecycle.provisioning.approval_required == true
	input.pci.account_lifecycle.modification.approval_required == true
	input.pci.account_lifecycle.termination.immediate_revocation == true
	input.pci.account_lifecycle.terminated_accounts.removed_within_90_days == true
	input.pci.account_lifecycle.inactive_accounts.disabled_after_90_days == true
}

# Vendor/supplier accounts managed
vendor_accounts_managed if {
	input.pci.vendor_accounts.disabled_when_not_in_use == true
	input.pci.vendor_accounts.monitored_when_active == true
	input.pci.vendor_accounts.time_limited == true
	input.pci.vendor_accounts.access_log.maintained == true
}

# =================================================================
# 8.3 - User authentication factors managed for all users
# =================================================================

# Password/passphrase requirements
password_requirements if {
	input.pci.passwords.minimum_length >= 12
	input.pci.passwords.complexity.required == true
	input.pci.passwords.numeric_and_alpha.required == true
	input.pci.passwords.history.count >= 4
	input.pci.passwords.max_age_days <= 90
	input.pci.passwords.lockout.after_attempts <= 6
	input.pci.passwords.lockout.duration_minutes >= 30
	input.pci.passwords.no_dictionary_words == true
}

# First-time password change required
first_use_password_change if {
	input.pci.passwords.first_use.change_required == true
	input.pci.passwords.reset.immediate_change_required == true
	input.pci.passwords.temporary.single_use == true
}

# Authentication factors protected
authentication_factors_protected if {
	input.pci.auth_factors.stored.encrypted == true
	input.pci.auth_factors.transmission.encrypted == true
	input.pci.auth_factors.display.masked_on_screen == true
	input.pci.auth_factors.service_providers.different_from_customers == true
}

# =================================================================
# 8.4 - Multi-factor authentication (MFA) implemented
# =================================================================

# MFA required for all non-console admin access to CDE
mfa_for_cde_admin if {
	input.pci.mfa.cde_admin_access.required == true
	input.pci.mfa.non_console_admin.required == true
	input.pci.mfa.factors.at_least_two == true
	input.pci.mfa.factors.different_categories == true
}

# MFA required for all remote network access
mfa_for_remote_access if {
	input.pci.mfa.remote_access.required == true
	input.pci.mfa.vpn.mfa_enforced == true
	input.pci.mfa.remote_desktop.mfa_enforced == true
}

# MFA required for all users accessing CDE (v4.0 requirement)
mfa_for_all_cde_access if {
	input.pci.mfa.all_cde_access.required == true
	input.pci.mfa.user_cde_access.enforced == true
}

# MFA system configuration
mfa_system_secure if {
	input.pci.mfa.replay_attacks.prevented == true
	input.pci.mfa.bypass.not_possible_by_any_single_admin == true
	input.pci.mfa.factors.cannot_be_same_type == true
}

# =================================================================
# 8.5 - Multi-factor authentication systems configured to prevent misuse
# =================================================================

mfa_not_susceptible_to_replay if {
	input.pci.mfa.otp.time_based == true
	input.pci.mfa.otp.single_use == true
	input.pci.mfa.push_notifications.number_matching == true
}

# =================================================================
# 8.6 - Use of application and system accounts managed
# =================================================================

system_application_accounts if {
	input.pci.system_accounts.interactive_use.prohibited_unless_exceptional == true
	input.pci.system_accounts.authentication.managed == true
	input.pci.system_accounts.credentials.in_vault == true
	input.pci.system_accounts.credentials.rotation.automated == true
	input.pci.system_accounts.review.performed_periodically == true
}

# =================================================================
# Scoring
# =================================================================

pci_requirement_8_compliant if {
	authentication_policies_established
	authentication_roles_defined
	unique_user_ids
	account_lifecycle_managed
	vendor_accounts_managed
	password_requirements
	first_use_password_change
	authentication_factors_protected
	mfa_for_cde_admin
	mfa_for_remote_access
	mfa_for_all_cde_access
	mfa_system_secure
	system_application_accounts
}

pci_requirement_8_score := score if {
	controls := [
		authentication_policies_established,
		authentication_roles_defined,
		unique_user_ids,
		account_lifecycle_managed,
		vendor_accounts_managed,
		password_requirements,
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
	},
	"requirement_8_3": {
		"password_requirements": password_requirements,
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
	"requirement_8_6": {
		"system_accounts": system_application_accounts,
	},
	"overall_score": pci_requirement_8_score,
	"overall_compliant": pci_requirement_8_compliant,
}
