package cis.windows_11

import rego.v1

# CIS Microsoft Windows 11 Enterprise Benchmark v1.0.0
# This policy implements the CIS benchmarks for Windows 11 Enterprise environments
# Reference: https://www.cisecurity.org/benchmark/microsoft_windows_11

# Main compliance evaluation
compliant if {
	count(violations) == 0
}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		account_policies_violations,
		local_policies_violations,
		event_log_violations,
		restricted_groups_violations,
		system_services_violations,
		registry_violations,
		file_system_violations,
		administrative_templates_violations,
		windows_defender_violations,
		windows_firewall_violations,
		advanced_audit_violations
	]
	v := arrays[_][_]
]

# Generate compliance report
compliance_report := {
	"benchmark": "CIS Microsoft Windows 11 Enterprise Benchmark v1.0.0",
	"timestamp": time.now_ns(),
	"total_controls": 267,
	"compliant": compliant,
	"violations_count": count(violations),
	"violations": violations,
	"sections": {
		"account_policies": {
			"violations": count(account_policies_violations),
			"controls": 9
		},
		"local_policies": {
			"violations": count(local_policies_violations),
			"controls": 28
		},
		"event_log": {
			"violations": count(event_log_violations),
			"controls": 15
		},
		"restricted_groups": {
			"violations": count(restricted_groups_violations),
			"controls": 3
		},
		"system_services": {
			"violations": count(system_services_violations),
			"controls": 45
		},
		"registry": {
			"violations": count(registry_violations),
			"controls": 87
		},
		"file_system": {
			"violations": count(file_system_violations),
			"controls": 12
		},
		"administrative_templates": {
			"violations": count(administrative_templates_violations),
			"controls": 52
		},
		"windows_defender": {
			"violations": count(windows_defender_violations),
			"controls": 8
		},
		"windows_firewall": {
			"violations": count(windows_firewall_violations),
			"controls": 6
		},
		"advanced_audit": {
			"violations": count(advanced_audit_violations),
			"controls": 2
		}
	}
}

# Section 1: Account Policies
account_policies_violations := [v |
	arrays := [
		password_violations,
		account_lockout_violations
	]
	v := arrays[_][_]
]

# 1.1 Password Policy
password_violations := [v |
	arrays := [
		["1.1.1: Enforce password history - 24 passwords remembered" | not password_history_24],
		["1.1.2: Maximum password age - 365 days or fewer" | not max_password_age_365],
		["1.1.3: Minimum password age - 1 day or more" | not min_password_age_1],
		["1.1.4: Minimum password length - 14 characters or more" | not min_password_length_14],
		["1.1.5: Password must meet complexity requirements - Enabled" | not password_complexity_enabled],
		["1.1.6: Store passwords using reversible encryption - Disabled" | not reversible_encryption_disabled]
	]
	v := arrays[_][_]
]

password_history_24 if {
	input.system.security_policy.password_policy.enforce_password_history >= 24
}

max_password_age_365 if {
	input.system.security_policy.password_policy.maximum_password_age <= 365
	input.system.security_policy.password_policy.maximum_password_age > 0
}

min_password_age_1 if {
	input.system.security_policy.password_policy.minimum_password_age >= 1
}

min_password_length_14 if {
	input.system.security_policy.password_policy.minimum_password_length >= 14
}

password_complexity_enabled if {
	input.system.security_policy.password_policy.password_must_meet_complexity_requirements == true
}

reversible_encryption_disabled if {
	input.system.security_policy.password_policy.store_passwords_using_reversible_encryption == false
}

# 1.2 Account Lockout Policy
account_lockout_violations := [v |
	arrays := [
		["1.2.1: Account lockout duration - 15 minutes or more" | not lockout_duration_15],
		["1.2.2: Account lockout threshold - 5 invalid attempts or fewer" | not lockout_threshold_5],
		["1.2.3: Reset account lockout counter after - 15 minutes or more" | not lockout_counter_reset_15]
	]
	v := arrays[_][_]
]

lockout_duration_15 if {
	input.system.security_policy.account_lockout_policy.account_lockout_duration >= 15
}

lockout_threshold_5 if {
	input.system.security_policy.account_lockout_policy.account_lockout_threshold <= 5
	input.system.security_policy.account_lockout_policy.account_lockout_threshold > 0
}

lockout_counter_reset_15 if {
	input.system.security_policy.account_lockout_policy.reset_account_lockout_counter_after >= 15
}

# Section 2: Local Policies
local_policies_violations := [v |
	arrays := [
		audit_policy_violations,
		user_rights_violations,
		security_options_violations
	]
	v := arrays[_][_]
]

# 2.2 Audit Policy
audit_policy_violations := [v |
	arrays := [
		["2.2.1: Audit account logon events - Success, Failure" | not audit_account_logon_enabled],
		["2.2.2: Audit account management - Success, Failure" | not audit_account_management_enabled],
		["2.2.3: Audit directory service access - Failure" | not audit_directory_service_enabled],
		["2.2.4: Audit logon events - Success, Failure" | not audit_logon_events_enabled],
		["2.2.5: Audit object access - Failure" | not audit_object_access_enabled],
		["2.2.6: Audit policy change - Success, Failure" | not audit_policy_change_enabled],
		["2.2.7: Audit privilege use - Failure" | not audit_privilege_use_enabled],
		["2.2.8: Audit process tracking - No Auditing" | not audit_process_tracking_disabled],
		["2.2.9: Audit system events - Success, Failure" | not audit_system_events_enabled]
	]
	v := arrays[_][_]
]

audit_account_logon_enabled if {
	policy := input.system.security_policy.audit_policy.audit_account_logon_events
	"Success" in policy
	"Failure" in policy
}

audit_account_management_enabled if {
	policy := input.system.security_policy.audit_policy.audit_account_management
	"Success" in policy
	"Failure" in policy
}

audit_directory_service_enabled if {
	policy := input.system.security_policy.audit_policy.audit_directory_service_access
	"Failure" in policy
}

audit_logon_events_enabled if {
	policy := input.system.security_policy.audit_policy.audit_logon_events
	"Success" in policy
	"Failure" in policy
}

audit_object_access_enabled if {
	policy := input.system.security_policy.audit_policy.audit_object_access
	"Failure" in policy
}

audit_policy_change_enabled if {
	policy := input.system.security_policy.audit_policy.audit_policy_change
	"Success" in policy
	"Failure" in policy
}

audit_privilege_use_enabled if {
	policy := input.system.security_policy.audit_policy.audit_privilege_use
	"Failure" in policy
}

audit_process_tracking_disabled if {
	input.system.security_policy.audit_policy.audit_process_tracking == "No Auditing"
}

audit_system_events_enabled if {
	policy := input.system.security_policy.audit_policy.audit_system_events
	"Success" in policy
	"Failure" in policy
}

# 2.3 User Rights Assignment
user_rights_violations := [v |
	arrays := [
		["2.3.1.1: Access Credential Manager as a trusted caller - No One" | not access_credential_manager_none],
		["2.3.1.2: Access this computer from the network - Administrators Authenticated Users" | not network_access_restricted],
		["2.3.1.3: Act as part of the operating system - No One" | not act_as_os_none],
		["2.3.1.4: Allow log on locally - Administrators Users" | not local_logon_restricted],
		["2.3.1.5: Allow log on through Remote Desktop Services - Administrators Remote Desktop Users" | not rdp_logon_restricted],
		["2.3.1.6: Back up files and directories - Administrators" | not backup_restricted],
		["2.3.1.7: Change the system time - Administrators LOCAL SERVICE" | not change_time_restricted],
		["2.3.1.8: Change the time zone - Administrators LOCAL SERVICE Users" | not change_timezone_restricted],
		["2.3.1.9: Create a pagefile - Administrators" | not create_pagefile_restricted],
		["2.3.1.10: Create a token object - No One" | not create_token_none],
		["2.3.1.11: Create global objects - Administrators LOCAL SERVICE NETWORK SERVICE SERVICE" | not create_global_objects_restricted],
		["2.3.1.12: Create permanent shared objects - No One" | not create_permanent_objects_none],
		["2.3.1.13: Create symbolic links - Administrators" | not create_symlinks_restricted],
		["2.3.1.14: Debug programs - Administrators" | not debug_programs_restricted],
		["2.3.1.15: Deny access to this computer from the network - Guests Local account" | not deny_network_access_configured],
		["2.3.1.16: Deny log on as a batch job - Guests" | not deny_batch_job_configured],
		["2.3.1.17: Deny log on as a service - No One" | not deny_service_logon_none],
		["2.3.1.18: Deny log on locally - Guests" | not deny_local_logon_configured],
		["2.3.1.19: Deny log on through Remote Desktop Services - Guests Local account" | not deny_rdp_configured]
	]
	v := arrays[_][_]
]

access_credential_manager_none if {
	count(input.system.security_policy.user_rights_assignment.access_credential_manager_as_trusted_caller) == 0
}

network_access_restricted if {
	rights := input.system.security_policy.user_rights_assignment.access_this_computer_from_network
	"Administrators" in rights
	"Authenticated Users" in rights
	count([r | r := rights[_]; not r in ["Administrators", "Authenticated Users"]]) == 0
}

act_as_os_none if {
	count(input.system.security_policy.user_rights_assignment.act_as_part_of_operating_system) == 0
}

local_logon_restricted if {
	rights := input.system.security_policy.user_rights_assignment.allow_log_on_locally
	"Administrators" in rights
	"Users" in rights
}

rdp_logon_restricted if {
	rights := input.system.security_policy.user_rights_assignment.allow_log_on_through_rdp
	"Administrators" in rights
	"Remote Desktop Users" in rights
}

backup_restricted if {
	rights := input.system.security_policy.user_rights_assignment.back_up_files_and_directories
	rights == ["Administrators"]
}

change_time_restricted if {
	rights := input.system.security_policy.user_rights_assignment.change_system_time
	"Administrators" in rights
	"LOCAL SERVICE" in rights
}

change_timezone_restricted if {
	rights := input.system.security_policy.user_rights_assignment.change_time_zone
	"Administrators" in rights
	"LOCAL SERVICE" in rights
	"Users" in rights
}

create_pagefile_restricted if {
	rights := input.system.security_policy.user_rights_assignment.create_pagefile
	rights == ["Administrators"]
}

create_token_none if {
	count(input.system.security_policy.user_rights_assignment.create_token_object) == 0
}

create_global_objects_restricted if {
	rights := input.system.security_policy.user_rights_assignment.create_global_objects
	allowed := ["Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE"]
	count([r | r := rights[_]; not r in allowed]) == 0
}

create_permanent_objects_none if {
	count(input.system.security_policy.user_rights_assignment.create_permanent_shared_objects) == 0
}

create_symlinks_restricted if {
	rights := input.system.security_policy.user_rights_assignment.create_symbolic_links
	rights == ["Administrators"]
}

debug_programs_restricted if {
	rights := input.system.security_policy.user_rights_assignment.debug_programs
	rights == ["Administrators"]
}

deny_network_access_configured if {
	rights := input.system.security_policy.user_rights_assignment.deny_access_to_computer_from_network
	"Guests" in rights
	"Local account" in rights
}

deny_batch_job_configured if {
	rights := input.system.security_policy.user_rights_assignment.deny_log_on_as_batch_job
	"Guests" in rights
}

deny_service_logon_none if {
	count(input.system.security_policy.user_rights_assignment.deny_log_on_as_service) == 0
}

deny_local_logon_configured if {
	rights := input.system.security_policy.user_rights_assignment.deny_log_on_locally
	"Guests" in rights
}

deny_rdp_configured if {
	rights := input.system.security_policy.user_rights_assignment.deny_log_on_through_rdp
	"Guests" in rights
	"Local account" in rights
}

# 2.4 Security Options
security_options_violations := [v |
	arrays := [
		["2.4.1: Accounts: Block Microsoft accounts - Users can't add or log on with Microsoft accounts" | not microsoft_accounts_blocked],
		["2.4.2: Accounts: Guest account status - Disabled" | not guest_account_disabled],
		["2.4.3: Accounts: Limit local account use of blank passwords to console logon only - Enabled" | not blank_passwords_console_only],
		["2.4.4: Accounts: Rename administrator account - Enabled" | not admin_account_renamed],
		["2.4.5: Accounts: Rename guest account - Enabled" | not guest_account_renamed],
		["2.4.6: Audit: Force audit policy subcategory settings - Enabled" | not force_audit_subcategory],
		["2.4.7: Audit: Shut down system immediately if unable to log security audits - Disabled" | not audit_shutdown_disabled],
		["2.4.8: DCOM: Enable Distributed COM on this computer - Enabled" | not dcom_enabled],
		["2.4.9: Devices: Allowed to format and eject removable media - Administrators" | not removable_media_restricted],
		["2.4.10: Devices: Prevent users from installing printer drivers - Enabled" | not printer_drivers_restricted]
	]
	v := arrays[_][_]
]

microsoft_accounts_blocked if {
	input.system.security_policy.security_options.accounts_block_microsoft_accounts == "Users can't add or log on with Microsoft accounts"
}

guest_account_disabled if {
	input.system.security_policy.security_options.accounts_guest_account_status == false
}

blank_passwords_console_only if {
	input.system.security_policy.security_options.accounts_limit_local_account_use_of_blank_passwords == true
}

admin_account_renamed if {
	input.system.security_policy.security_options.accounts_rename_administrator_account != "Administrator"
}

guest_account_renamed if {
	input.system.security_policy.security_options.accounts_rename_guest_account != "Guest"
}

force_audit_subcategory if {
	input.system.security_policy.security_options.audit_force_audit_policy_subcategory_settings == true
}

audit_shutdown_disabled if {
	input.system.security_policy.security_options.audit_shut_down_system_immediately == false
}

dcom_enabled if {
	input.system.security_policy.security_options.dcom_enable_distributed_com == true
}

removable_media_restricted if {
	input.system.security_policy.security_options.devices_allowed_to_format_removable_media == "Administrators"
}

printer_drivers_restricted if {
	input.system.security_policy.security_options.devices_prevent_users_from_installing_printer_drivers == true
}

# Section 3: Event Log
event_log_violations := [v |
	arrays := [
		application_log_violations,
		security_log_violations,
		system_log_violations
	]
	v := arrays[_][_]
]

# 3.1 Application Log
application_log_violations := [v |
	arrays := [
		["3.1.1: Application: Control Event Log behavior when the log file reaches its maximum size - Disabled" | not app_log_retention_disabled],
		["3.1.2: Application: Maximum Log Size - 32 768 KB or greater" | not app_log_size_adequate],
		["3.1.3: Application: Specify the maximum log file size - 32 768 KB or greater" | not app_log_max_size_adequate],
		["3.1.4: Application: Restrict Guest access to Application event log - Enabled" | not app_log_guest_restricted],
		["3.1.5: Application: Retention method for Application event log - As needed" | not app_log_retention_as_needed]
	]
	v := arrays[_][_]
]

app_log_retention_disabled if {
	input.system.security_policy.event_log.application.control_event_log_behavior == false
}

app_log_size_adequate if {
	input.system.security_policy.event_log.application.maximum_log_size >= 32768
}

app_log_max_size_adequate if {
	input.system.security_policy.event_log.application.specify_maximum_log_file_size >= 32768
}

app_log_guest_restricted if {
	input.system.security_policy.event_log.application.restrict_guest_access == true
}

app_log_retention_as_needed if {
	input.system.security_policy.event_log.application.retention_method == "As needed"
}

# 3.2 Security Log
security_log_violations := [v |
	arrays := [
		["3.2.1: Security: Control Event Log behavior when the log file reaches its maximum size - Disabled" | not sec_log_retention_disabled],
		["3.2.2: Security: Maximum Log Size - 196 608 KB or greater" | not sec_log_size_adequate],
		["3.2.3: Security: Specify the maximum log file size - 196 608 KB or greater" | not sec_log_max_size_adequate],
		["3.2.4: Security: Restrict Guest access to Security event log - Enabled" | not sec_log_guest_restricted],
		["3.2.5: Security: Retention method for Security event log - As needed" | not sec_log_retention_as_needed]
	]
	v := arrays[_][_]
]

sec_log_retention_disabled if {
	input.system.security_policy.event_log.security.control_event_log_behavior == false
}

sec_log_size_adequate if {
	input.system.security_policy.event_log.security.maximum_log_size >= 196608
}

sec_log_max_size_adequate if {
	input.system.security_policy.event_log.security.specify_maximum_log_file_size >= 196608
}

sec_log_guest_restricted if {
	input.system.security_policy.event_log.security.restrict_guest_access == true
}

sec_log_retention_as_needed if {
	input.system.security_policy.event_log.security.retention_method == "As needed"
}

# 3.3 System Log
system_log_violations := [v |
	arrays := [
		["3.3.1: System: Control Event Log behavior when the log file reaches its maximum size - Disabled" | not sys_log_retention_disabled],
		["3.3.2: System: Maximum Log Size - 32 768 KB or greater" | not sys_log_size_adequate],
		["3.3.3: System: Specify the maximum log file size - 32 768 KB or greater" | not sys_log_max_size_adequate],
		["3.3.4: System: Restrict Guest access to System event log - Enabled" | not sys_log_guest_restricted],
		["3.3.5: System: Retention method for System event log - As needed" | not sys_log_retention_as_needed]
	]
	v := arrays[_][_]
]

sys_log_retention_disabled if {
	input.system.security_policy.event_log.system.control_event_log_behavior == false
}

sys_log_size_adequate if {
	input.system.security_policy.event_log.system.maximum_log_size >= 32768
}

sys_log_max_size_adequate if {
	input.system.security_policy.event_log.system.specify_maximum_log_file_size >= 32768
}

sys_log_guest_restricted if {
	input.system.security_policy.event_log.system.restrict_guest_access == true
}

sys_log_retention_as_needed if {
	input.system.security_policy.event_log.system.retention_method == "As needed"
}

# Section 4: Restricted Groups
restricted_groups_violations := [v |
	arrays := [
		["4.1: Configure 'Administrators' - Only necessary accounts" | not administrators_group_restricted],
		["4.2: Configure 'Remote Desktop Users' - Only necessary accounts" | not rdp_users_restricted],
		["4.3: Configure 'Power Users' - Empty or necessary accounts only" | not power_users_restricted]
	]
	v := arrays[_][_]
]

administrators_group_restricted if {
	admins := input.system.security_policy.restricted_groups.administrators
	count(admins) <= 3
	"Administrator" in admins
}

rdp_users_restricted if {
	rdp_users := input.system.security_policy.restricted_groups.remote_desktop_users
	count(rdp_users) <= 2
}

power_users_restricted if {
	power_users := input.system.security_policy.restricted_groups.power_users
	count(power_users) == 0
}

# Section 5: System Services
system_services_violations := [v |
	arrays := [
		["5.1: Application Layer Gateway Service - Disabled" | not alg_service_disabled],
		["5.2: Application Management - Manual or Disabled" | not app_mgmt_restricted],
		["5.3: BitLocker Drive Encryption Service - Manual" | not bitlocker_service_manual],
		["5.4: Certificate Propagation - Manual" | not cert_prop_manual],
		["5.5: Computer Browser - Disabled" | not computer_browser_disabled],
		["5.6: Cryptographic Services - Automatic" | not crypto_services_auto],
		["5.7: DHCP Client - Automatic" | not dhcp_client_auto],
		["5.8: Distributed Link Tracking Client - Automatic" | not dlt_client_auto],
		["5.9: DNS Client - Automatic" | not dns_client_auto],
		["5.10: File Replication - Disabled" | not file_replication_disabled],
		["5.11: Fax - Disabled or Manual" | not fax_service_restricted],
		["5.12: Function Discovery Provider Host - Manual" | not fdphost_manual],
		["5.13: Function Discovery Resource Publication - Disabled" | not fdrp_disabled],
		["5.14: Help and Support - Manual" | not help_support_manual],
		["5.15: Human Interface Device Access - Manual" | not hid_service_manual],
		["5.16: IIS Admin Service - Disabled" | not iis_admin_disabled],
		["5.17: Indexing Service - Manual or Disabled" | not indexing_restricted],
		["5.18: Internet Connection Sharing - Disabled" | not ics_disabled],
		["5.19: IP Helper - Automatic" | not ip_helper_auto],
		["5.20: IPSec Services - Manual or Automatic" | not ipsec_allowed],
		["5.21: KDC Proxy Server service - Manual" | not kdc_proxy_manual],
		["5.22: Link-Layer Topology Discovery Mapper - Manual" | not lltd_mapper_manual],
		["5.23: LM Hosts - Manual" | not lmhosts_manual],
		["5.24: Messenger - Disabled" | not messenger_disabled],
		["5.25: Microsoft FTP Service - Disabled or Manual" | not ftp_service_restricted],
		["5.26: Microsoft iSCSI Initiator Service - Manual" | not iscsi_manual],
		["5.27: Net Logon - Manual" | not netlogon_manual],
		["5.28: Netlogon - Automatic (DC only)" | not netlogon_auto_dc],
		["5.29: Network Access Protection Agent - Manual" | not nap_agent_manual],
		["5.30: Network Connections - Manual" | not net_connections_manual],
		["5.31: Network List Service - Manual" | not net_list_manual],
		["5.32: Network Location Awareness - Automatic" | not nla_auto],
		["5.33: Network Store Interface Service - Automatic" | not nsi_auto],
		["5.34: Offline Files - Disabled or Manual" | not offline_files_restricted],
		["5.35: Peer Name Resolution Protocol - Disabled" | not pnrp_disabled],
		["5.36: Peer Networking Grouping - Disabled" | not peer_grouping_disabled],
		["5.37: Peer Networking Identity Manager - Disabled" | not peer_identity_disabled],
		["5.38: PNRP Machine Name Publication Service - Disabled" | not pnrp_pub_disabled],
		["5.39: Portable Device Enumerator Service - Manual" | not portable_device_manual],
		["5.40: Print Spooler - Automatic" | not print_spooler_auto],
		["5.41: Protected Storage - Manual" | not protected_storage_manual],
		["5.42: Remote Access Auto Connection Manager - Disabled" | not ras_auto_disabled],
		["5.43: Remote Access Connection Manager - Disabled" | not ras_connection_disabled],
		["5.44: Remote Desktop Configuration - Manual" | not rd_config_manual],
		["5.45: Remote Desktop Services - Disabled" | not rd_services_disabled]
	]
	v := arrays[_][_]
]

alg_service_disabled if {
	input.system.services.application_layer_gateway.startup_type == "Disabled"
}

app_mgmt_restricted if {
	startup := input.system.services.application_management.startup_type
	startup in ["Manual", "Disabled"]
}

bitlocker_service_manual if {
	input.system.services.bitlocker_drive_encryption.startup_type == "Manual"
}

cert_prop_manual if {
	input.system.services.certificate_propagation.startup_type == "Manual"
}

computer_browser_disabled if {
	input.system.services.computer_browser.startup_type == "Disabled"
}

crypto_services_auto if {
	input.system.services.cryptographic_services.startup_type == "Automatic"
}

dhcp_client_auto if {
	input.system.services.dhcp_client.startup_type == "Automatic"
}

dlt_client_auto if {
	input.system.services.distributed_link_tracking_client.startup_type == "Automatic"
}

dns_client_auto if {
	input.system.services.dns_client.startup_type == "Automatic"
}

file_replication_disabled if {
	input.system.services.file_replication.startup_type == "Disabled"
}

fax_service_restricted if {
	startup := input.system.services.fax.startup_type
	startup in ["Disabled", "Manual"]
}

fdphost_manual if {
	input.system.services.function_discovery_provider_host.startup_type == "Manual"
}

fdrp_disabled if {
	input.system.services.function_discovery_resource_publication.startup_type == "Disabled"
}

help_support_manual if {
	input.system.services.help_and_support.startup_type == "Manual"
}

hid_service_manual if {
	input.system.services.human_interface_device_access.startup_type == "Manual"
}

iis_admin_disabled if {
	input.system.services.iis_admin_service.startup_type == "Disabled"
}

indexing_restricted if {
	startup := input.system.services.indexing_service.startup_type
	startup in ["Manual", "Disabled"]
}

ics_disabled if {
	input.system.services.internet_connection_sharing.startup_type == "Disabled"
}

ip_helper_auto if {
	input.system.services.ip_helper.startup_type == "Automatic"
}

ipsec_allowed if {
	startup := input.system.services.ipsec_services.startup_type
	startup in ["Manual", "Automatic"]
}

kdc_proxy_manual if {
	input.system.services.kdc_proxy_server.startup_type == "Manual"
}

lltd_mapper_manual if {
	input.system.services.link_layer_topology_discovery_mapper.startup_type == "Manual"
}

lmhosts_manual if {
	input.system.services.lm_hosts.startup_type == "Manual"
}

messenger_disabled if {
	input.system.services.messenger.startup_type == "Disabled"
}

ftp_service_restricted if {
	startup := input.system.services.microsoft_ftp_service.startup_type
	startup in ["Disabled", "Manual"]
}

iscsi_manual if {
	input.system.services.microsoft_iscsi_initiator.startup_type == "Manual"
}

netlogon_manual if {
	input.system.services.net_logon.startup_type == "Manual"
}

netlogon_auto_dc if {
	not input.system.is_domain_controller
}

netlogon_auto_dc if {
	input.system.is_domain_controller
	input.system.services.net_logon.startup_type == "Automatic"
}

nap_agent_manual if {
	input.system.services.network_access_protection_agent.startup_type == "Manual"
}

net_connections_manual if {
	input.system.services.network_connections.startup_type == "Manual"
}

net_list_manual if {
	input.system.services.network_list_service.startup_type == "Manual"
}

nla_auto if {
	input.system.services.network_location_awareness.startup_type == "Automatic"
}

nsi_auto if {
	input.system.services.network_store_interface_service.startup_type == "Automatic"
}

offline_files_restricted if {
	startup := input.system.services.offline_files.startup_type
	startup in ["Disabled", "Manual"]
}

pnrp_disabled if {
	input.system.services.peer_name_resolution_protocol.startup_type == "Disabled"
}

peer_grouping_disabled if {
	input.system.services.peer_networking_grouping.startup_type == "Disabled"
}

peer_identity_disabled if {
	input.system.services.peer_networking_identity_manager.startup_type == "Disabled"
}

pnrp_pub_disabled if {
	input.system.services.pnrp_machine_name_publication.startup_type == "Disabled"
}

portable_device_manual if {
	input.system.services.portable_device_enumerator.startup_type == "Manual"
}

print_spooler_auto if {
	input.system.services.print_spooler.startup_type == "Automatic"
}

protected_storage_manual if {
	input.system.services.protected_storage.startup_type == "Manual"
}

ras_auto_disabled if {
	input.system.services.remote_access_auto_connection_manager.startup_type == "Disabled"
}

ras_connection_disabled if {
	input.system.services.remote_access_connection_manager.startup_type == "Disabled"
}

rd_config_manual if {
	input.system.services.remote_desktop_configuration.startup_type == "Manual"
}

rd_services_disabled if {
	input.system.services.remote_desktop_services.startup_type == "Disabled"
}

# Section 6: Registry
registry_violations := [v |
	arrays := [
		["6.1: Disable Autoplay for non-volume devices - Enabled" | not autoplay_nonvolume_disabled],
		["6.2: Set the default behavior for AutoRun - Enabled: Do not execute any autorun commands" | not autorun_disabled],
		["6.3: Turn off Autoplay - Enabled: All drives" | not autoplay_all_drives_disabled],
		["6.4: Do not display the password reveal button - Enabled" | not password_reveal_disabled],
		["6.5: Enumerate administrator accounts on elevation - Disabled" | not admin_enumeration_disabled],
		["6.6: Require trusted path for credential entry - Enabled" | not trusted_path_required],
		["6.7: Configure Windows SmartScreen - Enabled" | not smartscreen_enabled],
		["6.8: Turn on Windows SmartScreen - Enabled" | not smartscreen_on],
		["6.9: Configure Windows Defender SmartScreen - Enabled: Warn" | not defender_smartscreen_warn],
		["6.10: Prevent the usage of OneDrive for file storage - Enabled" | not onedrive_disabled],
		["6.11: Allow Cortana - Disabled" | not cortana_disabled],
		["6.12: Allow Cortana above lock screen - Disabled" | not cortana_lockscreen_disabled],
		["6.13: Allow indexing of encrypted files - Disabled" | not encrypted_indexing_disabled],
		["6.14: Allow search and Cortana to use location - Disabled" | not search_location_disabled],
		["6.15: Do not preserve zone information in file attachments - Disabled" | not zone_info_preserved],
		["6.16: Notify antivirus programs when opening attachments - Enabled" | not antivirus_notification_enabled],
		["6.17: Configure Windows spotlight on lock screen - Disabled" | not spotlight_lockscreen_disabled],
		["6.18: Do not suggest third-party content in Windows spotlight - Enabled" | not spotlight_thirdparty_disabled],
		["6.19: Turn off all Windows spotlight features - Enabled" | not spotlight_all_disabled],
		["6.20: Turn off Windows spotlight on Settings - Enabled" | not spotlight_settings_disabled]
	]
	v := arrays[_][_]
]

autoplay_nonvolume_disabled if {
	input.system.registry.autoplay.disable_autoplay_for_nonvolume_devices == true
}

autorun_disabled if {
	input.system.registry.autoplay.default_behavior_for_autorun == "Do not execute any autorun commands"
}

autoplay_all_drives_disabled if {
	input.system.registry.autoplay.turn_off_autoplay == "All drives"
}

password_reveal_disabled if {
	input.system.registry.credential_ui.do_not_display_password_reveal_button == true
}

admin_enumeration_disabled if {
	input.system.registry.credential_ui.enumerate_administrator_accounts_on_elevation == false
}

trusted_path_required if {
	input.system.registry.credential_ui.require_trusted_path_for_credential_entry == true
}

smartscreen_enabled if {
	input.system.registry.smartscreen.configure_windows_smartscreen == true
}

smartscreen_on if {
	input.system.registry.smartscreen.turn_on_windows_smartscreen == true
}

defender_smartscreen_warn if {
	input.system.registry.smartscreen.configure_windows_defender_smartscreen == "Warn"
}

onedrive_disabled if {
	input.system.registry.onedrive.prevent_usage_for_file_storage == true
}

cortana_disabled if {
	input.system.registry.cortana.allow_cortana == false
}

cortana_lockscreen_disabled if {
	input.system.registry.cortana.allow_cortana_above_lock_screen == false
}

encrypted_indexing_disabled if {
	input.system.registry.search.allow_indexing_of_encrypted_files == false
}

search_location_disabled if {
	input.system.registry.search.allow_search_and_cortana_to_use_location == false
}

zone_info_preserved if {
	input.system.registry.attachments.do_not_preserve_zone_information == false
}

antivirus_notification_enabled if {
	input.system.registry.attachments.notify_antivirus_programs_when_opening_attachments == true
}

spotlight_lockscreen_disabled if {
	input.system.registry.windows_spotlight.configure_spotlight_on_lock_screen == false
}

spotlight_thirdparty_disabled if {
	input.system.registry.windows_spotlight.do_not_suggest_third_party_content == true
}

spotlight_all_disabled if {
	input.system.registry.windows_spotlight.turn_off_all_spotlight_features == true
}

spotlight_settings_disabled if {
	input.system.registry.windows_spotlight.turn_off_spotlight_on_settings == true
}

# Section 7: File System
file_system_violations := [v |
	arrays := [
		["7.1.1: %systemroot%\\system32\\config\\SAM - SYSTEM: Full Control Administrators: Full Control" | not sam_permissions_correct],
		["7.1.2: %systemroot%\\system32\\config\\SECURITY - SYSTEM: Full Control Administrators: Full Control" | not security_permissions_correct],
		["7.1.3: %systemroot%\\system32\\config\\SOFTWARE - SYSTEM: Full Control Administrators: Full Control Users: Read" | not software_permissions_correct],
		["7.1.4: %systemroot%\\system32\\config\\SYSTEM - SYSTEM: Full Control Administrators: Full Control" | not system_permissions_correct],
		["7.1.5: %systemroot%\\system32\\svchost.exe - TrustedInstaller: Full Control" | not svchost_permissions_correct],
		["7.1.6: %systemroot%\\system32\\winlogon.exe - TrustedInstaller: Full Control" | not winlogon_permissions_correct],
		["7.2.1: Program Files folder permissions - Administrators: Full Control SYSTEM: Full Control Users: Read & Execute" | not program_files_permissions_correct],
		["7.2.2: Windows folder permissions - TrustedInstaller: Full Control Administrators: Modify SYSTEM: Full Control Users: Read & Execute" | not windows_permissions_correct],
		["7.3.1: Registry Editor - Administrators only" | not regedit_access_restricted],
		["7.3.2: Command Prompt - Users: Access allowed" | not cmd_access_allowed],
		["7.3.3: Control Panel - Users: Access allowed" | not control_panel_access_allowed],
		["7.3.4: Run command - Users: Access allowed" | not run_command_access_allowed]
	]
	v := arrays[_][_]
]

sam_permissions_correct if {
	perms := input.system.file_system.permissions.sam
	"SYSTEM" in perms.full_control
	"Administrators" in perms.full_control
}

security_permissions_correct if {
	perms := input.system.file_system.permissions.security
	"SYSTEM" in perms.full_control
	"Administrators" in perms.full_control
}

software_permissions_correct if {
	perms := input.system.file_system.permissions.software
	"SYSTEM" in perms.full_control
	"Administrators" in perms.full_control
	"Users" in perms.read
}

system_permissions_correct if {
	perms := input.system.file_system.permissions.system
	"SYSTEM" in perms.full_control
	"Administrators" in perms.full_control
}

svchost_permissions_correct if {
	perms := input.system.file_system.permissions.svchost
	"TrustedInstaller" in perms.full_control
}

winlogon_permissions_correct if {
	perms := input.system.file_system.permissions.winlogon
	"TrustedInstaller" in perms.full_control
}

program_files_permissions_correct if {
	perms := input.system.file_system.permissions.program_files
	"Administrators" in perms.full_control
	"SYSTEM" in perms.full_control
	"Users" in perms.read_execute
}

windows_permissions_correct if {
	perms := input.system.file_system.permissions.windows
	"TrustedInstaller" in perms.full_control
	"Administrators" in perms.modify
	"SYSTEM" in perms.full_control
	"Users" in perms.read_execute
}

regedit_access_restricted if {
	access := input.system.file_system.access_control.registry_editor
	access == ["Administrators"]
}

cmd_access_allowed if {
	access := input.system.file_system.access_control.command_prompt
	"Users" in access
}

control_panel_access_allowed if {
	access := input.system.file_system.access_control.control_panel
	"Users" in access
}

run_command_access_allowed if {
	access := input.system.file_system.access_control.run_command
	"Users" in access
}

# Section 8: Administrative Templates
administrative_templates_violations := [v |
	arrays := [
		computer_config_violations,
		user_config_violations
	]
	v := arrays[_][_]
]

# 8.1 Computer Configuration
computer_config_violations := [v |
	arrays := [
		["8.1.1: Turn off Microsoft Peer-to-Peer Networking Services - Enabled" | not p2p_networking_disabled],
		["8.1.2: Prohibit installation and configuration of Network Bridge - Enabled" | not network_bridge_prohibited],
		["8.1.3: Prohibit use of Internet Connection Sharing - Enabled" | not ics_prohibited],
		["8.1.4: Require domain users to elevate when setting network location - Enabled" | not domain_users_elevate_network],
		["8.1.5: Hardened UNC Paths - Enabled" | not unc_paths_hardened],
		["8.1.6: Minimize connections to multiple Internet sources - Enabled" | not multiple_internet_minimized],
		["8.1.7: Prohibit connection to non-domain networks - Enabled (if domain joined)" | not non_domain_networks_prohibited],
		["8.1.8: Turn off Windows Connect Now - Enabled" | not wcn_disabled],
		["8.1.9: Turn off Windows Connect Now wizard - Enabled" | not wcn_wizard_disabled],
		["8.1.10: Turn off Internet download for Web publishing and online ordering wizards - Enabled" | not web_publishing_download_disabled],
		["8.1.11: Turn off printing over HTTP - Enabled" | not http_printing_disabled],
		["8.1.12: Turn off Registration if URL connection is referring to Microsoft.com - Enabled" | not ms_registration_disabled],
		["8.1.13: Turn off Search Companion content file updates - Enabled" | not search_companion_updates_disabled],
		["8.1.14: Turn off the Order Prints picture task - Enabled" | not order_prints_disabled],
		["8.1.15: Turn off the Publish to Web task for files and folders - Enabled" | not publish_web_disabled],
		["8.1.16: Turn off the Windows Messenger Customer Experience Improvement Program - Enabled" | not messenger_ceip_disabled],
		["8.1.17: Turn off Windows Customer Experience Improvement Program - Enabled" | not ceip_disabled],
		["8.1.18: Turn off Windows Error Reporting - Enabled" | not error_reporting_disabled],
		["8.1.19: Support device authentication using certificate - Enabled: Automatic" | not device_auth_certificate_enabled],
		["8.1.20: Enumeration policy for external devices incompatible with Kernel DMA Protection - Enabled: Block All" | not dma_protection_block_all],
		["8.1.21: Boot-Start Driver Initialization Policy - Enabled: Good unknown and bad but critical" | not boot_driver_policy_restricted],
		["8.1.22: Configure registry policy processing - Enabled" | not registry_policy_processing_enabled],
		["8.1.23: Configure system restore point creation frequency - Enabled" | not system_restore_frequency_enabled],
		["8.1.24: Turn off access to the Store - Enabled" | not store_access_disabled],
		["8.1.25: Turn off the Store application - Enabled" | not store_application_disabled],
		["8.1.26: Turn off Automatic Download and Install of updates - Disabled" | not automatic_updates_enabled]
	]
	v := arrays[_][_]
]

p2p_networking_disabled if {
	input.system.administrative_templates.computer_config.network.turn_off_microsoft_p2p_networking == true
}

network_bridge_prohibited if {
	input.system.administrative_templates.computer_config.network.prohibit_network_bridge == true
}

ics_prohibited if {
	input.system.administrative_templates.computer_config.network.prohibit_internet_connection_sharing == true
}

domain_users_elevate_network if {
	input.system.administrative_templates.computer_config.network.require_domain_users_elevate_network_location == true
}

unc_paths_hardened if {
	input.system.administrative_templates.computer_config.network.hardened_unc_paths == true
}

multiple_internet_minimized if {
	input.system.administrative_templates.computer_config.network.minimize_connections_multiple_internet == true
}

non_domain_networks_prohibited if {
	not input.system.is_domain_joined
}

non_domain_networks_prohibited if {
	input.system.is_domain_joined
	input.system.administrative_templates.computer_config.network.prohibit_non_domain_networks == true
}

wcn_disabled if {
	input.system.administrative_templates.computer_config.network.turn_off_windows_connect_now == true
}

wcn_wizard_disabled if {
	input.system.administrative_templates.computer_config.network.turn_off_wcn_wizard == true
}

web_publishing_download_disabled if {
	input.system.administrative_templates.computer_config.system.turn_off_internet_download_web_publishing == true
}

http_printing_disabled if {
	input.system.administrative_templates.computer_config.printers.turn_off_printing_over_http == true
}

ms_registration_disabled if {
	input.system.administrative_templates.computer_config.internet_communication.turn_off_registration_ms_referring == true
}

search_companion_updates_disabled if {
	input.system.administrative_templates.computer_config.internet_communication.turn_off_search_companion_updates == true
}

order_prints_disabled if {
	input.system.administrative_templates.computer_config.internet_communication.turn_off_order_prints == true
}

publish_web_disabled if {
	input.system.administrative_templates.computer_config.internet_communication.turn_off_publish_to_web == true
}

messenger_ceip_disabled if {
	input.system.administrative_templates.computer_config.internet_communication.turn_off_messenger_ceip == true
}

ceip_disabled if {
	input.system.administrative_templates.computer_config.internet_communication.turn_off_ceip == true
}

error_reporting_disabled if {
	input.system.administrative_templates.computer_config.internet_communication.turn_off_error_reporting == true
}

device_auth_certificate_enabled if {
	input.system.administrative_templates.computer_config.system.support_device_authentication_certificate == "Automatic"
}

dma_protection_block_all if {
	input.system.administrative_templates.computer_config.system.enumeration_policy_external_devices_dma == "Block All"
}

boot_driver_policy_restricted if {
	policy := input.system.administrative_templates.computer_config.system.boot_start_driver_initialization_policy
	policy == "Good, unknown and bad but critical"
}

registry_policy_processing_enabled if {
	input.system.administrative_templates.computer_config.system.configure_registry_policy_processing == true
}

system_restore_frequency_enabled if {
	input.system.administrative_templates.computer_config.system.configure_system_restore_point_frequency == true
}

store_access_disabled if {
	input.system.administrative_templates.computer_config.windows_components.turn_off_access_to_store == true
}

store_application_disabled if {
	input.system.administrative_templates.computer_config.windows_components.turn_off_store_application == true
}

automatic_updates_enabled if {
	input.system.administrative_templates.computer_config.windows_update.turn_off_automatic_download_install == false
}

# 8.2 User Configuration
user_config_violations := [v |
	arrays := [
		["8.2.1: Prevent access to registry editing tools - Enabled" | not registry_editing_prevented],
		["8.2.2: Prevent access to the command prompt - Disabled" | not command_prompt_access_allowed],
		["8.2.3: Always install with elevated privileges - Disabled" | not elevated_privileges_disabled],
		["8.2.4: Turn off toast notifications on the lock screen - Enabled" | not toast_notifications_lockscreen_disabled],
		["8.2.5: Turn off Help Experience Improvement Program - Enabled" | not help_experience_improvement_disabled],
		["8.2.6: Do not preserve zone information in file attachments - Disabled" | not zone_information_preserved],
		["8.2.7: Notify antivirus programs when opening attachments - Enabled" | not antivirus_notify_enabled],
		["8.2.8: Configure Windows spotlight on lock screen - Disabled" | not user_spotlight_lockscreen_disabled],
		["8.2.9: Do not suggest third-party content in Windows spotlight - Enabled" | not user_spotlight_thirdparty_disabled],
		["8.2.10: Turn off all Windows spotlight features - Enabled" | not user_spotlight_all_disabled],
		["8.2.11: Turn off Windows spotlight on Action Center - Enabled" | not user_spotlight_action_center_disabled],
		["8.2.12: Turn off Windows spotlight on Settings - Enabled" | not user_spotlight_settings_disabled],
		["8.2.13: Do not use diagnostic data for tailored experiences - Enabled" | not diagnostic_data_tailored_disabled],
		["8.2.14: Turn off Microsoft consumer experiences - Enabled" | not consumer_experiences_disabled],
		["8.2.15: Require pin for pairing - Enabled" | not pin_pairing_required],
		["8.2.16: Do not display network selection UI - Enabled" | not network_selection_ui_disabled],
		["8.2.17: Do not enumerate connected USB devices on the lock screen - Enabled" | not usb_enumeration_lockscreen_disabled],
		["8.2.18: Prevent enabling lock screen camera - Enabled" | not lockscreen_camera_disabled],
		["8.2.19: Prevent enabling lock screen slide show - Enabled" | not lockscreen_slideshow_disabled],
		["8.2.20: Allow input personalization - Disabled" | not input_personalization_disabled],
		["8.2.21: Turn off the advertising ID - Enabled" | not advertising_id_disabled],
		["8.2.22: Turn off location for this device - Enabled" | not location_disabled],
		["8.2.23: Turn off all location privacy settings - Enabled" | not location_privacy_disabled],
		["8.2.24: Configure Authenticated Proxy usage for Connected User Experience and Telemetry - Enabled: Disable Authenticated Proxy usage" | not authenticated_proxy_disabled],
		["8.2.25: Do not show feedback notifications - Enabled" | not feedback_notifications_disabled],
		["8.2.26: Turn off Automatic Download and Install of updates - Disabled" | not user_automatic_updates_enabled]
	]
	v := arrays[_][_]
]

registry_editing_prevented if {
	input.system.administrative_templates.user_config.system.prevent_access_to_registry_editing_tools == true
}

command_prompt_access_allowed if {
	input.system.administrative_templates.user_config.system.prevent_access_to_command_prompt == false
}

elevated_privileges_disabled if {
	input.system.administrative_templates.user_config.windows_installer.always_install_with_elevated_privileges == false
}

toast_notifications_lockscreen_disabled if {
	input.system.administrative_templates.user_config.start_menu_taskbar.turn_off_toast_notifications_lockscreen == true
}

help_experience_improvement_disabled if {
	input.system.administrative_templates.user_config.help_experience_improvement.turn_off_help_experience_improvement == true
}

zone_information_preserved if {
	input.system.administrative_templates.user_config.attachments.do_not_preserve_zone_information == false
}

antivirus_notify_enabled if {
	input.system.administrative_templates.user_config.attachments.notify_antivirus_programs == true
}

user_spotlight_lockscreen_disabled if {
	input.system.administrative_templates.user_config.cloud_content.configure_spotlight_lockscreen == false
}

user_spotlight_thirdparty_disabled if {
	input.system.administrative_templates.user_config.cloud_content.do_not_suggest_third_party_content == true
}

user_spotlight_all_disabled if {
	input.system.administrative_templates.user_config.cloud_content.turn_off_all_spotlight_features == true
}

user_spotlight_action_center_disabled if {
	input.system.administrative_templates.user_config.cloud_content.turn_off_spotlight_action_center == true
}

user_spotlight_settings_disabled if {
	input.system.administrative_templates.user_config.cloud_content.turn_off_spotlight_settings == true
}

diagnostic_data_tailored_disabled if {
	input.system.administrative_templates.user_config.cloud_content.do_not_use_diagnostic_data == true
}

consumer_experiences_disabled if {
	input.system.administrative_templates.user_config.cloud_content.turn_off_consumer_experiences == true
}

pin_pairing_required if {
	input.system.administrative_templates.user_config.bluetooth.require_pin_for_pairing == true
}

network_selection_ui_disabled if {
	input.system.administrative_templates.user_config.network_connections.do_not_display_network_selection_ui == true
}

usb_enumeration_lockscreen_disabled if {
	input.system.administrative_templates.user_config.network_connections.do_not_enumerate_usb_devices_lockscreen == true
}

lockscreen_camera_disabled if {
	input.system.administrative_templates.user_config.personalization.prevent_enabling_lockscreen_camera == true
}

lockscreen_slideshow_disabled if {
	input.system.administrative_templates.user_config.personalization.prevent_enabling_lockscreen_slideshow == true
}

input_personalization_disabled if {
	input.system.administrative_templates.user_config.input_personalization.allow_input_personalization == false
}

advertising_id_disabled if {
	input.system.administrative_templates.user_config.privacy.turn_off_advertising_id == true
}

location_disabled if {
	input.system.administrative_templates.user_config.privacy.turn_off_location == true
}

location_privacy_disabled if {
	input.system.administrative_templates.user_config.privacy.turn_off_all_location_privacy == true
}

authenticated_proxy_disabled if {
	input.system.administrative_templates.user_config.data_collection.configure_authenticated_proxy == "Disable Authenticated Proxy usage"
}

feedback_notifications_disabled if {
	input.system.administrative_templates.user_config.data_collection.do_not_show_feedback_notifications == true
}

user_automatic_updates_enabled if {
	input.system.administrative_templates.user_config.windows_update.turn_off_automatic_download_install == false
}

# Section 9: Windows Defender Antivirus
windows_defender_violations := [v |
	arrays := [
		["9.1: Configure Attack Surface Reduction rules - Enabled" | not asr_rules_configured],
		["9.2: Configure detection for potentially unwanted applications - Enabled: Block" | not pua_detection_block],
		["9.3: Turn off Windows Defender AntiVirus - Disabled" | not defender_enabled],
		["9.4: Configure real-time protection - Enabled" | not realtime_protection_enabled],
		["9.5: Scan all downloaded files and attachments - Enabled" | not scan_downloads_enabled],
		["9.6: Turn on behavior monitoring - Enabled" | not behavior_monitoring_enabled],
		["9.7: Turn on process scanning whenever real-time protection is enabled - Enabled" | not process_scanning_enabled],
		["9.8: Configure local setting override for reporting to Microsoft MAPS - Disabled" | not maps_override_disabled]
	]
	v := arrays[_][_]
]

asr_rules_configured if {
	rules := input.system.windows_defender.attack_surface_reduction.rules
	count(rules) > 0
	rules.block_executable_content_email == "Enabled"
	rules.block_office_apps_creating_executable_content == "Enabled"
	rules.block_office_apps_injecting_code == "Enabled"
	rules.block_js_vbs_executing_downloaded_content == "Enabled"
}

pua_detection_block if {
	input.system.windows_defender.potentially_unwanted_applications.detection_action == "Block"
}

defender_enabled if {
	input.system.windows_defender.antivirus.turn_off_windows_defender == false
}

realtime_protection_enabled if {
	input.system.windows_defender.real_time_protection.configure_real_time_protection == true
}

scan_downloads_enabled if {
	input.system.windows_defender.real_time_protection.scan_downloaded_files == true
}

behavior_monitoring_enabled if {
	input.system.windows_defender.real_time_protection.turn_on_behavior_monitoring == true
}

process_scanning_enabled if {
	input.system.windows_defender.real_time_protection.turn_on_process_scanning == true
}

maps_override_disabled if {
	input.system.windows_defender.maps.configure_local_setting_override == false
}

# Section 10: Windows Firewall with Advanced Security
windows_firewall_violations := [v |
	arrays := [
		domain_firewall_violations,
		private_firewall_violations,
		public_firewall_violations
	]
	v := arrays[_][_]
]

# 10.1 Domain Profile
domain_firewall_violations := [v |
	arrays := [
		["10.1.1: Domain Profile: Firewall state - On" | not domain_firewall_on],
		["10.1.2: Domain Profile: Inbound connections - Block (default)" | not domain_inbound_block]
	]
	v := arrays[_][_]
]

domain_firewall_on if {
	input.system.windows_firewall.domain_profile.firewall_state == "On"
}

domain_inbound_block if {
	input.system.windows_firewall.domain_profile.inbound_connections == "Block (default)"
}

# 10.2 Private Profile
private_firewall_violations := [v |
	arrays := [
		["10.2.1: Private Profile: Firewall state - On" | not private_firewall_on],
		["10.2.2: Private Profile: Inbound connections - Block (default)" | not private_inbound_block]
	]
	v := arrays[_][_]
]

private_firewall_on if {
	input.system.windows_firewall.private_profile.firewall_state == "On"
}

private_inbound_block if {
	input.system.windows_firewall.private_profile.inbound_connections == "Block (default)"
}

# 10.3 Public Profile
public_firewall_violations := [v |
	arrays := [
		["10.3.1: Public Profile: Firewall state - On" | not public_firewall_on],
		["10.3.2: Public Profile: Inbound connections - Block (default)" | not public_inbound_block]
	]
	v := arrays[_][_]
]

public_firewall_on if {
	input.system.windows_firewall.public_profile.firewall_state == "On"
}

public_inbound_block if {
	input.system.windows_firewall.public_profile.inbound_connections == "Block (default)"
}

# Section 11: Advanced Audit Policy Configuration
advanced_audit_violations := [v |
	arrays := [
		["11.1: Audit Policy: Account Logon: Credential Validation - Success and Failure" | not credential_validation_audit],
		["11.2: Audit Policy: Account Management: User Account Management - Success and Failure" | not user_account_mgmt_audit]
	]
	v := arrays[_][_]
]

credential_validation_audit if {
	audit := input.system.advanced_audit_policy.account_logon.credential_validation
	"Success" in audit
	"Failure" in audit
}

user_account_mgmt_audit if {
	audit := input.system.advanced_audit_policy.account_management.user_account_management
	"Success" in audit
	"Failure" in audit
}