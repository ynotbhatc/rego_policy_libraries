package cis.windows.server2022

import rego.v1

# CIS Microsoft Windows Server 2022 Benchmark
# Operating System Security Configuration

# CIS 1.1.1 - Ensure 'Enforce password history' is set to '24 or more password(s)'
password_history_enforced if {
    input.security_policy.password_history >= 24
}

# CIS 1.1.2 - Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'
password_max_age if {
    input.security_policy.password_max_age <= 365
    input.security_policy.password_max_age > 0
}

# CIS 1.1.3 - Ensure 'Minimum password age' is set to '1 or more day(s)'
password_min_age if {
    input.security_policy.password_min_age >= 1
}

# CIS 1.1.4 - Ensure 'Minimum password length' is set to '14 or more character(s)'
password_min_length if {
    input.security_policy.password_min_length >= 14
}

# CIS 1.1.5 - Ensure 'Password must meet complexity requirements' is set to 'Enabled'
password_complexity_enabled if {
    input.security_policy.password_complexity == true
}

# CIS 1.1.6 - Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
reversible_encryption_disabled if {
    input.security_policy.reversible_encryption == false
}

# CIS 1.2.1 - Ensure 'Account lockout duration' is set to '15 or more minute(s)'
account_lockout_duration if {
    input.security_policy.account_lockout_duration >= 15
}

# CIS 1.2.2 - Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'
account_lockout_threshold if {
    input.security_policy.account_lockout_threshold <= 5
    input.security_policy.account_lockout_threshold > 0
}

# CIS 1.2.3 - Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
lockout_counter_reset if {
    input.security_policy.lockout_counter_reset >= 15
}

# CIS 2.2.1 - Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
access_credential_manager_restricted if {
    count(input.user_rights.access_credential_manager) == 0
}

# CIS 2.2.2 - Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users'
network_access_restricted if {
    input.user_rights.network_access == ["Administrators", "Authenticated Users"]
}

# CIS 2.2.3 - Ensure 'Act as part of the operating system' is set to 'No One'
act_as_os_restricted if {
    count(input.user_rights.act_as_os) == 0
}

# CIS 2.2.4 - Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
adjust_memory_quotas_restricted if {
    expected := ["Administrators", "LOCAL SERVICE", "NETWORK SERVICE"]
    input.user_rights.adjust_memory_quotas == expected
}

# CIS 2.2.5 - Ensure 'Allow log on locally' is set to 'Administrators'
local_logon_restricted if {
    input.user_rights.local_logon == ["Administrators"]
}

# CIS 2.2.6 - Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators'
rdp_logon_restricted if {
    input.user_rights.rdp_logon == ["Administrators"]
}

# CIS 2.2.7 - Ensure 'Back up files and directories' is set to 'Administrators'
backup_privilege_restricted if {
    input.user_rights.backup_privilege == ["Administrators"]
}

# CIS 2.2.8 - Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
change_system_time_restricted if {
    expected := ["Administrators", "LOCAL SERVICE"]
    input.user_rights.change_system_time == expected
}

# CIS 2.2.9 - Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
change_time_zone_restricted if {
    expected := ["Administrators", "LOCAL SERVICE"]
    input.user_rights.change_time_zone == expected
}

# CIS 2.2.10 - Ensure 'Create a pagefile' is set to 'Administrators'
create_pagefile_restricted if {
    input.user_rights.create_pagefile == ["Administrators"]
}

# CIS 2.2.11 - Ensure 'Create a token object' is set to 'No One'
create_token_restricted if {
    count(input.user_rights.create_token) == 0
}

# CIS 2.2.12 - Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
create_global_objects_restricted if {
    expected := ["Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE"]
    input.user_rights.create_global_objects == expected
}

# CIS 2.2.13 - Ensure 'Create permanent shared objects' is set to 'No One'
create_permanent_objects_restricted if {
    count(input.user_rights.create_permanent_objects) == 0
}

# CIS 2.2.14 - Ensure 'Create symbolic links' is set to 'Administrators'
create_symbolic_links_restricted if {
    input.user_rights.create_symbolic_links == ["Administrators"]
}

# CIS 2.2.15 - Ensure 'Debug programs' is set to 'Administrators'
debug_programs_restricted if {
    input.user_rights.debug_programs == ["Administrators"]
}

# CIS 2.2.16 - Ensure 'Deny access to this computer from the network' includes 'Guests'
deny_network_access_includes_guests if {
    contains(input.user_rights.deny_network_access, "Guests")
}

# CIS 2.2.17 - Ensure 'Deny log on as a batch job' includes 'Guests'
deny_batch_logon_includes_guests if {
    contains(input.user_rights.deny_batch_logon, "Guests")
}

# CIS 2.2.18 - Ensure 'Deny log on as a service' includes 'Guests'
deny_service_logon_includes_guests if {
    contains(input.user_rights.deny_service_logon, "Guests")
}

# CIS 2.2.19 - Ensure 'Deny log on locally' includes 'Guests'
deny_local_logon_includes_guests if {
    contains(input.user_rights.deny_local_logon, "Guests")
}

# CIS 2.2.20 - Ensure 'Deny log on through Remote Desktop Services' includes 'Guests'
deny_rdp_logon_includes_guests if {
    contains(input.user_rights.deny_rdp_logon, "Guests")
}

# CIS 2.3.1.1 - Ensure 'Accounts: Administrator account status' is set to 'Disabled'
administrator_account_disabled if {
    input.security_options.administrator_account_status == "Disabled"
}

# CIS 2.3.1.2 - Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
block_microsoft_accounts if {
    input.security_options.block_microsoft_accounts == "Users can't add or log on with Microsoft accounts"
}

# CIS 2.3.1.3 - Ensure 'Accounts: Guest account status' is set to 'Disabled'
guest_account_disabled if {
    input.security_options.guest_account_status == "Disabled"
}

# CIS 2.3.1.4 - Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
limit_blank_passwords if {
    input.security_options.limit_blank_passwords == "Enabled"
}

# CIS 2.3.1.5 - Ensure 'Accounts: Rename administrator account' is configured
rename_administrator_account if {
    input.security_options.administrator_account_name != "Administrator"
    input.security_options.administrator_account_name != ""
}

# CIS 2.3.1.6 - Ensure 'Accounts: Rename guest account' is configured
rename_guest_account if {
    input.security_options.guest_account_name != "Guest"
    input.security_options.guest_account_name != ""
}

# CIS 2.3.2.1 - Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
force_audit_policy_subcategory if {
    input.security_options.force_audit_policy_subcategory == "Enabled"
}

# CIS 2.3.2.2 - Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
shutdown_on_audit_failure if {
    input.security_options.shutdown_on_audit_failure == "Disabled"
}

# CIS 2.3.4.1 - Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
format_removable_media_restricted if {
    input.security_options.format_removable_media == "Administrators"
}

# CIS 2.3.4.2 - Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
prevent_printer_driver_install if {
    input.security_options.prevent_printer_driver_install == "Enabled"
}

# CIS 2.3.6.1 - Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
encrypt_secure_channel if {
    input.security_options.encrypt_secure_channel == "Enabled"
}

# CIS 2.3.6.2 - Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
encrypt_secure_channel_when_possible if {
    input.security_options.encrypt_secure_channel_when_possible == "Enabled"
}

# CIS 2.3.6.3 - Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
sign_secure_channel_when_possible if {
    input.security_options.sign_secure_channel_when_possible == "Enabled"
}

# CIS 2.3.6.4 - Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
disable_machine_password_changes if {
    input.security_options.disable_machine_password_changes == "Disabled"
}

# CIS 2.3.6.5 - Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
machine_password_max_age if {
    input.security_options.machine_password_max_age <= 30
    input.security_options.machine_password_max_age > 0
}

# CIS 2.3.6.6 - Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
require_strong_session_key if {
    input.security_options.require_strong_session_key == "Enabled"
}

# Aggregate Windows Server 2022 compliance
windows_server_compliant if {
    password_history_enforced
    password_max_age
    password_min_age
    password_min_length
    password_complexity_enabled
    reversible_encryption_disabled
    account_lockout_duration
    account_lockout_threshold
    lockout_counter_reset
    access_credential_manager_restricted
    network_access_restricted
    act_as_os_restricted
    adjust_memory_quotas_restricted
    local_logon_restricted
    rdp_logon_restricted
    backup_privilege_restricted
    change_system_time_restricted
    change_time_zone_restricted
    create_pagefile_restricted
    create_token_restricted
    create_global_objects_restricted
    create_permanent_objects_restricted
    create_symbolic_links_restricted
    debug_programs_restricted
    deny_network_access_includes_guests
    deny_batch_logon_includes_guests
    deny_service_logon_includes_guests
    deny_local_logon_includes_guests
    deny_rdp_logon_includes_guests
    administrator_account_disabled
    block_microsoft_accounts
    guest_account_disabled
    limit_blank_passwords
    rename_administrator_account
    rename_guest_account
    force_audit_policy_subcategory
    shutdown_on_audit_failure
    format_removable_media_restricted
    prevent_printer_driver_install
    encrypt_secure_channel
    encrypt_secure_channel_when_possible
    sign_secure_channel_when_possible
    disable_machine_password_changes
    machine_password_max_age
    require_strong_session_key
}

# Detailed Windows Server 2022 compliance report
windows_server_compliance := {
    "password_history_enforced": password_history_enforced,
    "password_max_age": password_max_age,
    "password_min_age": password_min_age,
    "password_min_length": password_min_length,
    "password_complexity_enabled": password_complexity_enabled,
    "reversible_encryption_disabled": reversible_encryption_disabled,
    "account_lockout_duration": account_lockout_duration,
    "account_lockout_threshold": account_lockout_threshold,
    "lockout_counter_reset": lockout_counter_reset,
    "access_credential_manager_restricted": access_credential_manager_restricted,
    "network_access_restricted": network_access_restricted,
    "act_as_os_restricted": act_as_os_restricted,
    "adjust_memory_quotas_restricted": adjust_memory_quotas_restricted,
    "local_logon_restricted": local_logon_restricted,
    "rdp_logon_restricted": rdp_logon_restricted,
    "backup_privilege_restricted": backup_privilege_restricted,
    "change_system_time_restricted": change_system_time_restricted,
    "change_time_zone_restricted": change_time_zone_restricted,
    "create_pagefile_restricted": create_pagefile_restricted,
    "create_token_restricted": create_token_restricted,
    "create_global_objects_restricted": create_global_objects_restricted,
    "create_permanent_objects_restricted": create_permanent_objects_restricted,
    "create_symbolic_links_restricted": create_symbolic_links_restricted,
    "debug_programs_restricted": debug_programs_restricted,
    "deny_network_access_includes_guests": deny_network_access_includes_guests,
    "deny_batch_logon_includes_guests": deny_batch_logon_includes_guests,
    "deny_service_logon_includes_guests": deny_service_logon_includes_guests,
    "deny_local_logon_includes_guests": deny_local_logon_includes_guests,
    "deny_rdp_logon_includes_guests": deny_rdp_logon_includes_guests,
    "administrator_account_disabled": administrator_account_disabled,
    "block_microsoft_accounts": block_microsoft_accounts,
    "guest_account_disabled": guest_account_disabled,
    "limit_blank_passwords": limit_blank_passwords,
    "rename_administrator_account": rename_administrator_account,
    "rename_guest_account": rename_guest_account,
    "force_audit_policy_subcategory": force_audit_policy_subcategory,
    "shutdown_on_audit_failure": shutdown_on_audit_failure,
    "format_removable_media_restricted": format_removable_media_restricted,
    "prevent_printer_driver_install": prevent_printer_driver_install,
    "encrypt_secure_channel": encrypt_secure_channel,
    "encrypt_secure_channel_when_possible": encrypt_secure_channel_when_possible,
    "sign_secure_channel_when_possible": sign_secure_channel_when_possible,
    "disable_machine_password_changes": disable_machine_password_changes,
    "machine_password_max_age": machine_password_max_age,
    "require_strong_session_key": require_strong_session_key,
    "overall_compliant": windows_server_compliant
}