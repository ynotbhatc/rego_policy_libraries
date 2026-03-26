package cis_windows_server_2022.local_policies

# CIS Windows Server 2022 Benchmark v3.0.0 - Section 2.2: User Rights Assignment

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	[v | some v in user_rights_violations],
	[v | some v in security_settings_violations],
)

# CIS 2.2.1: Access Credential Manager as a trusted caller = No One
user_rights_violations contains msg if {
	count(input.local_policies.access_credential_manager) > 0
	msg := "CIS 2.2.1: 'Access Credential Manager as a trusted caller' should be set to No One"
}

# CIS 2.2.2: Access this computer from the network = Administrators, Authenticated Users
user_rights_violations contains msg if {
	not input.local_policies.network_access_includes_authenticated_users
	msg := "CIS 2.2.2: 'Access this computer from the network' should include Authenticated Users"
}

# CIS 2.2.5: Allow log on locally = Administrators
user_rights_violations contains msg if {
	not input.local_policies.local_logon_restricted
	msg := "CIS 2.2.5: 'Allow log on locally' is not restricted to Administrators"
}

# CIS 2.2.6: Allow log on through Remote Desktop Services
user_rights_violations contains msg if {
	not input.local_policies.rdp_logon_restricted
	msg := "CIS 2.2.6: 'Allow log on through Remote Desktop Services' is not restricted to Administrators and Remote Desktop Users"
}

# CIS 2.2.7: Back up files and directories = Administrators
user_rights_violations contains msg if {
	not input.local_policies.backup_files_restricted
	msg := "CIS 2.2.7: 'Back up files and directories' is not restricted to Administrators"
}

# CIS 2.2.11: Create symbolic links = Administrators
user_rights_violations contains msg if {
	not input.local_policies.create_symlinks_restricted
	msg := "CIS 2.2.11: 'Create symbolic links' is not restricted to Administrators"
}

# CIS 2.2.13: Debug programs = Administrators
user_rights_violations contains msg if {
	not input.local_policies.debug_programs_restricted
	msg := "CIS 2.2.13: 'Debug programs' is not restricted to Administrators"
}

# CIS 2.2.14: Deny access to this computer from the network = includes Guests
user_rights_violations contains msg if {
	not input.local_policies.deny_network_access_includes_guests
	msg := "CIS 2.2.14: 'Deny access to this computer from the network' does not include Guests"
}

# CIS 2.2.15: Deny log on as a batch job = includes Guests
user_rights_violations contains msg if {
	not input.local_policies.deny_batch_logon_includes_guests
	msg := "CIS 2.2.15: 'Deny log on as a batch job' does not include Guests"
}

# CIS 2.2.16: Deny log on as a service = includes Guests
user_rights_violations contains msg if {
	not input.local_policies.deny_service_logon_includes_guests
	msg := "CIS 2.2.16: 'Deny log on as a service' does not include Guests"
}

# CIS 2.2.17: Deny log on locally = includes Guests
user_rights_violations contains msg if {
	not input.local_policies.deny_local_logon_includes_guests
	msg := "CIS 2.2.17: 'Deny log on locally' does not include Guests"
}

# CIS 2.2.18: Deny log on through Remote Desktop Services = includes Guests
user_rights_violations contains msg if {
	not input.local_policies.deny_rdp_logon_includes_guests
	msg := "CIS 2.2.18: 'Deny log on through Remote Desktop Services' does not include Guests"
}

# CIS 2.2.19: Enable computer and user accounts to be trusted for delegation = No One (MS only)
user_rights_violations contains msg if {
	input.local_policies.is_member_server
	count(input.local_policies.trusted_for_delegation) > 0
	msg := "CIS 2.2.19: 'Enable computer and user accounts to be trusted for delegation' should be No One (MS only)"
}

# CIS 2.2.21: Force shutdown from a remote system = Administrators
user_rights_violations contains msg if {
	not input.local_policies.remote_shutdown_restricted
	msg := "CIS 2.2.21: 'Force shutdown from a remote system' is not restricted to Administrators"
}

# CIS 2.2.26: Manage auditing and security log = Administrators
user_rights_violations contains msg if {
	not input.local_policies.manage_audit_log_restricted
	msg := "CIS 2.2.26: 'Manage auditing and security log' is not restricted to Administrators"
}

# CIS 2.2.32: Restore files and directories = Administrators
user_rights_violations contains msg if {
	not input.local_policies.restore_files_restricted
	msg := "CIS 2.2.32: 'Restore files and directories' is not restricted to Administrators"
}

# CIS 2.2.33: Shut down the system = Administrators
user_rights_violations contains msg if {
	not input.local_policies.shutdown_restricted
	msg := "CIS 2.2.33: 'Shut down the system' is not restricted to Administrators"
}

# CIS 2.2.35: Take ownership of files or other objects = Administrators
user_rights_violations contains msg if {
	not input.local_policies.take_ownership_restricted
	msg := "CIS 2.2.35: 'Take ownership of files or other objects' is not restricted to Administrators"
}

# Audit policy settings
security_settings_violations contains msg if {
	not input.local_policies.audit_force_subcategory_settings
	msg := "CIS 2.3.2.1: Audit: Force audit policy subcategory settings is not enabled"
}

security_settings_violations contains msg if {
	not input.local_policies.audit_shutdown_if_unable_to_log
	msg := "CIS 2.3.2.2: Audit: Shut down system immediately if unable to log security audits is not configured"
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"user_rights_violations": count(user_rights_violations),
	"security_settings_violations": count(security_settings_violations),
	"controls_checked": 20,
	"section": "2.2 User Rights Assignment",
	"benchmark": "CIS Windows Server 2022 v3.0.0",
}
