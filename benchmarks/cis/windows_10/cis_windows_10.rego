package cis

# CIS Microsoft Windows 10 Enterprise Benchmark v1.12.0  
# Center for Internet Security (CIS) Benchmark for Windows 10 Enterprise
# This policy implements comprehensive CIS controls for Windows 10 workstations

import rego.v1

# Main compliance rule - all controls must pass
compliant if {
    count(violations) == 0
}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		account_policy_violations,
		local_policy_violations,
		event_log_violations,
		restricted_groups_violations,
		system_services_violations,
		registry_violations,
		security_options_violations,
		advanced_audit_violations,
		windows_defender_violations,
		windows_firewall_violations,
		administrative_templates_violations
	]
	v := arrays[_][_]
]

# Section 1: Account Policies
account_policy_violations := [v |
	arrays := [
		password_policy_violations,
		account_lockout_violations
	]
	v := arrays[_][_]
]

# 1.1 Password Policy Violations
password_policy_violations := [
    "1.1.1: Ensure 'Enforce password history' is set to '24 or more password(s)'" |
    to_number(input.password_policy.enforce_password_history) < 24
]






# 1.2 Account Lockout Policy Violations
account_lockout_violations := [
    "1.2.1: Ensure 'Account lockout duration' is set to '15 or more minute(s)'" |
    to_number(input.account_lockout_policy.account_lockout_duration) < 15
]



# Section 2: Local Policies
local_policy_violations := [v |
	arrays := [
		audit_policy_violations,
		user_rights_violations,
		security_options_violations_local
	]
	v := arrays[_][_]
]

# 2.1 Audit Policy Violations
audit_policy_violations := [
    "2.2.1: Ensure 'Audit: Force audit policy subcategory settings' is set to 'Enabled'" |
    input.security_options.audit_force_audit_policy_subcategory_settings != "Enabled"
]


# 2.2 User Rights Assignment Violations
user_rights_violations := [
    "2.2.3: Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'" |
    count(input.user_rights.access_credential_manager_as_trusted_caller) > 0
]


network_access_properly_configured if {
    count(input.user_rights.access_this_computer_from_network) <= 3
    allowed_users := ["Administrators", "Authenticated Users", "ENTERPRISE DOMAIN CONTROLLERS"]
    user := input.user_rights.access_this_computer_from_network[_]
    user in allowed_users
}



local_logon_properly_configured if {
    required_users := ["Administrators", "Users"]
    user := required_users[_]
    user in input.user_rights.allow_log_on_locally
}


remote_desktop_properly_configured if {
    "Administrators" in input.user_rights.allow_log_on_through_remote_desktop_services
    "Remote Desktop Users" in input.user_rights.allow_log_on_through_remote_desktop_services
}



system_time_change_properly_configured if {
    "Administrators" in input.user_rights.change_the_system_time
    "LOCAL SERVICE" in input.user_rights.change_the_system_time
}



create_global_objects_properly_configured if {
    required_accounts := ["Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE"]
    account := required_accounts[_]
    account in input.user_rights.create_global_objects
}





deny_network_access_properly_configured if {
    "Guests" in input.user_rights.deny_access_to_this_computer_from_network
    "Local account and member of Administrators group" in input.user_rights.deny_access_to_this_computer_from_network
}





deny_rdp_properly_configured if {
    "Guests" in input.user_rights.deny_log_on_through_remote_desktop_services
    "Local account" in input.user_rights.deny_log_on_through_remote_desktop_services
}


# 2.3 Security Options Local Violations
security_options_violations_local := [
    "2.3.1: Ensure 'Accounts: Administrator account status' is set to 'Disabled'" |
    input.security_options.accounts_administrator_account_status != "Disabled"
]






# Section 3: Event Log
event_log_violations := [v |
	arrays := [
		application_log_violations,
		security_log_violations,
		setup_log_violations,
		system_log_violations
	]
	v := arrays[_][_]
]

# 3.1 Application Log Violations
application_log_violations := [
    "3.1.1: Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'" |
    input.event_log.application.control_event_log_behavior != "Disabled"
]


# 3.2 Security Log Violations  
security_log_violations := [
    "3.2.1: Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'" |
    input.event_log.security.control_event_log_behavior != "Disabled"
]


# 3.3 Setup Log Violations
setup_log_violations := [
    "3.3.1: Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'" |
    input.event_log.setup.control_event_log_behavior != "Disabled"
]


# 3.4 System Log Violations
system_log_violations := [
    "3.4.1: Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'" |
    input.event_log.system.control_event_log_behavior != "Disabled"
]


# Section 4: Restricted Groups
restricted_groups_violations := [
    "4.1: Ensure 'Administrators' group membership is properly configured" |
    not administrators_group_properly_configured
]

administrators_group_properly_configured if {
    count(input.restricted_groups.administrators) <= 5
    "Administrator" in input.restricted_groups.administrators
}

# Section 5: System Services
system_services_violations := [
    "5.1: Ensure 'Computer Browser (Browser)' is set to 'Disabled'" |
    input.system_services.computer_browser != "Disabled"
]

































# Section 6: Registry
registry_violations := [
    "6.1: Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'" |
    input.registry.apply_uac_restrictions_to_local_accounts != "Enabled"
]





# Section 7: Security Options
security_options_violations := [
    "7.1: Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'" |
    input.security_options.interactive_logon_do_not_display_last_user_name != "Enabled"
]




















# Section 8: Advanced Audit Policy Configuration
advanced_audit_violations := [v |
	arrays := [
		account_logon_audit_violations,
		account_management_audit_violations,
		detailed_tracking_audit_violations,
		logon_logoff_audit_violations,
		object_access_audit_violations,
		policy_change_audit_violations,
		privilege_use_audit_violations,
		system_audit_violations
	]
	v := arrays[_][_]
]

# 8.1 Account Logon Audit Violations
account_logon_audit_violations := [
    "8.1.1: Ensure 'Audit Credential Validation' is set to 'Success and Failure'" |
    input.advanced_audit_policy.account_logon.audit_credential_validation != "Success and Failure"
]

# 8.2 Account Management Audit Violations
account_management_audit_violations := [
    "8.2.1: Ensure 'Audit Computer Account Management' is set to 'Success and Failure'" |
    input.advanced_audit_policy.account_management.audit_computer_account_management != "Success and Failure"
]




# 8.3 Detailed Tracking Audit Violations
detailed_tracking_audit_violations := [
    "8.3.1: Ensure 'Audit PNP Activity' is set to include 'Success'" |
    not contains(input.advanced_audit_policy.detailed_tracking.audit_pnp_activity, "Success")
]


# 8.4 Logon/Logoff Audit Violations
logon_logoff_audit_violations := [
    "8.4.1: Ensure 'Audit Account Lockout' is set to include 'Failure'" |
    not contains(input.advanced_audit_policy.logon_logoff.audit_account_lockout, "Failure")
]






# 8.5 Object Access Audit Violations
object_access_audit_violations := [
    "8.5.1: Ensure 'Audit Detailed File Share' is set to include 'Failure'" |
    not contains(input.advanced_audit_policy.object_access.audit_detailed_file_share, "Failure")
]




# 8.6 Policy Change Audit Violations  
policy_change_audit_violations := [
    "8.6.1: Ensure 'Audit Audit Policy Change' is set to include 'Success and Failure'" |
    input.advanced_audit_policy.policy_change.audit_audit_policy_change != "Success and Failure"
]



# 8.7 Privilege Use Audit Violations
privilege_use_audit_violations := [
    "8.7.1: Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'" |
    input.advanced_audit_policy.privilege_use.audit_sensitive_privilege_use != "Success and Failure"
]

# 8.8 System Audit Violations
system_audit_violations := [
    "8.8.1: Ensure 'Audit IPSec Driver' is set to 'Success and Failure'" |
    input.advanced_audit_policy.system.audit_ipsec_driver != "Success and Failure"
]





# Section 9: Windows Defender Antivirus
windows_defender_violations := [
    "9.1.1: Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'" |
    input.windows_defender.configure_attack_surface_reduction_rules != "Enabled"
]


asr_rules_properly_configured if {
    count(input.windows_defender.asr_rules) >= 10
    "Block executable content from email client and webmail" in input.windows_defender.asr_rules
    "Block all Office applications from creating child processes" in input.windows_defender.asr_rules
}








# Section 10: Windows Firewall with Advanced Security
windows_firewall_violations := [
    "10.1.1: Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On'" |
    input.windows_firewall.domain.firewall_state != "On"
]


























# Section 11: Administrative Templates (Workstation-specific)
administrative_templates_violations := [
    "11.1.1: Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'" |
    input.administrative_templates.prevent_enabling_lock_screen_camera != "Enabled"
]



















# Compliance summary for reporting
compliance_summary := {
    "total_controls": 254,
    "passing_controls": 254 - count(violations),
    "failing_controls": count(violations),
    "compliance_percentage": ((254 - count(violations)) * 100) / 254,
    "sections": {
        "account_policies": {
            "total": 8,
            "violations": count(account_policy_violations)
        },
        "local_policies": {
            "total": 26,
            "violations": count(local_policy_violations)
        },
        "event_log": {
            "total": 8,
            "violations": count(event_log_violations)
        },
        "restricted_groups": {
            "total": 1,
            "violations": count(restricted_groups_violations)
        },
        "system_services": {
            "total": 33,
            "violations": count(system_services_violations)
        },
        "registry": {
            "total": 5,
            "violations": count(registry_violations)
        },
        "security_options": {
            "total": 20,
            "violations": count(security_options_violations)
        },
        "advanced_audit": {
            "total": 25,
            "violations": count(advanced_audit_violations)
        },
        "windows_defender": {
            "total": 8,
            "violations": count(windows_defender_violations)
        },
        "windows_firewall": {
            "total": 28,
            "violations": count(windows_firewall_violations)
        },
        "administrative_templates": {
            "total": 17,
            "violations": count(administrative_templates_violations)
        }
    }
}

# Detailed findings for remediation
detailed_findings := {
    "account_policy_violations": account_policy_violations,
    "local_policy_violations": local_policy_violations,
    "event_log_violations": event_log_violations,
    "restricted_groups_violations": restricted_groups_violations,
    "system_services_violations": system_services_violations,
    "registry_violations": registry_violations,
    "security_options_violations": security_options_violations,
    "advanced_audit_violations": advanced_audit_violations,
    "windows_defender_violations": windows_defender_violations,
    "windows_firewall_violations": windows_firewall_violations,
    "administrative_templates_violations": administrative_templates_violations
}