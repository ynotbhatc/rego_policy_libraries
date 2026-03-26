package cis_windows_server_2019.advanced_audit

# CIS Windows Server 2019 Benchmark v3.0.0 - Section 17: Advanced Audit Policy Configuration

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in account_logon_violations], [v | some v in account_management_violations]),
	array.concat([v | some v in object_access_violations], [v | some v in policy_change_violations]),
)

# CIS 17.1: Account Logon
account_logon_violations contains msg if {
	not input.audit_policy.credential_validation_success
	msg := "CIS 17.1.1: Audit Credential Validation - Success not configured"
}

account_logon_violations contains msg if {
	not input.audit_policy.credential_validation_failure
	msg := "CIS 17.1.1: Audit Credential Validation - Failure not configured"
}

# CIS 17.2: Account Management
account_management_violations contains msg if {
	not input.audit_policy.computer_account_management_success
	msg := "CIS 17.2.1: Audit Computer Account Management - Success not configured"
}

account_management_violations contains msg if {
	not input.audit_policy.other_account_management_events_success
	msg := "CIS 17.2.2: Audit Other Account Management Events - Success not configured"
}

account_management_violations contains msg if {
	not input.audit_policy.security_group_management_success
	msg := "CIS 17.2.3: Audit Security Group Management - Success not configured"
}

account_management_violations contains msg if {
	not input.audit_policy.user_account_management_success
	msg := "CIS 17.2.5: Audit User Account Management - Success not configured"
}

account_management_violations contains msg if {
	not input.audit_policy.user_account_management_failure
	msg := "CIS 17.2.5: Audit User Account Management - Failure not configured"
}

# CIS 17.3: Detailed Tracking
detailed_tracking_violations contains msg if {
	not input.audit_policy.process_creation_success
	msg := "CIS 17.3.1: Audit Process Creation - Success not configured (required for SACL)"
}

# CIS 17.5: Logon/Logoff
logon_violations contains msg if {
	not input.audit_policy.account_lockout_failure
	msg := "CIS 17.5.1: Audit Account Lockout - Failure not configured"
}

logon_violations contains msg if {
	not input.audit_policy.group_membership_success
	msg := "CIS 17.5.2: Audit Group Membership - Success not configured"
}

logon_violations contains msg if {
	not input.audit_policy.logoff_success
	msg := "CIS 17.5.3: Audit Logoff - Success not configured"
}

logon_violations contains msg if {
	not input.audit_policy.logon_success
	msg := "CIS 17.5.4: Audit Logon - Success not configured"
}

logon_violations contains msg if {
	not input.audit_policy.logon_failure
	msg := "CIS 17.5.4: Audit Logon - Failure not configured"
}

logon_violations contains msg if {
	not input.audit_policy.other_logon_logoff_success
	msg := "CIS 17.5.5: Audit Other Logon/Logoff Events - Success not configured"
}

logon_violations contains msg if {
	not input.audit_policy.other_logon_logoff_failure
	msg := "CIS 17.5.5: Audit Other Logon/Logoff Events - Failure not configured"
}

logon_violations contains msg if {
	not input.audit_policy.special_logon_success
	msg := "CIS 17.5.6: Audit Special Logon - Success not configured"
}

# CIS 17.6: Object Access
object_access_violations contains msg if {
	not input.audit_policy.file_share_failure
	msg := "CIS 17.6.1: Audit Detailed File Share - Failure not configured"
}

object_access_violations contains msg if {
	not input.audit_policy.other_object_access_success
	msg := "CIS 17.6.3: Audit Other Object Access Events - Success not configured"
}

object_access_violations contains msg if {
	not input.audit_policy.other_object_access_failure
	msg := "CIS 17.6.3: Audit Other Object Access Events - Failure not configured"
}

object_access_violations contains msg if {
	not input.audit_policy.removable_storage_success
	msg := "CIS 17.6.4: Audit Removable Storage - Success not configured"
}

object_access_violations contains msg if {
	not input.audit_policy.removable_storage_failure
	msg := "CIS 17.6.4: Audit Removable Storage - Failure not configured"
}

# CIS 17.7: Policy Change
policy_change_violations contains msg if {
	not input.audit_policy.audit_policy_change_success
	msg := "CIS 17.7.1: Audit Audit Policy Change - Success not configured"
}

policy_change_violations contains msg if {
	not input.audit_policy.audit_policy_change_failure
	msg := "CIS 17.7.1: Audit Audit Policy Change - Failure not configured"
}

policy_change_violations contains msg if {
	not input.audit_policy.authentication_policy_change_success
	msg := "CIS 17.7.2: Audit Authentication Policy Change - Success not configured"
}

policy_change_violations contains msg if {
	not input.audit_policy.mpssvc_rule_level_policy_change_success
	msg := "CIS 17.7.4: Audit MPSSVC Rule-Level Policy Change - Success not configured"
}

policy_change_violations contains msg if {
	not input.audit_policy.mpssvc_rule_level_policy_change_failure
	msg := "CIS 17.7.4: Audit MPSSVC Rule-Level Policy Change - Failure not configured"
}

policy_change_violations contains msg if {
	not input.audit_policy.other_policy_change_success
	msg := "CIS 17.7.5: Audit Other Policy Change Events - Success not configured"
}

# CIS 17.8: Privilege Use
privilege_use_violations contains msg if {
	not input.audit_policy.sensitive_privilege_use_success
	msg := "CIS 17.8.1: Audit Sensitive Privilege Use - Success not configured"
}

privilege_use_violations contains msg if {
	not input.audit_policy.sensitive_privilege_use_failure
	msg := "CIS 17.8.1: Audit Sensitive Privilege Use - Failure not configured"
}

# CIS 17.9: System
system_violations contains msg if {
	not input.audit_policy.ipsec_driver_success
	msg := "CIS 17.9.1: Audit IPsec Driver - Success not configured"
}

system_violations contains msg if {
	not input.audit_policy.other_system_events_success
	msg := "CIS 17.9.2: Audit Other System Events - Success not configured"
}

system_violations contains msg if {
	not input.audit_policy.security_state_change_success
	msg := "CIS 17.9.3: Audit Security State Change - Success not configured"
}

system_violations contains msg if {
	not input.audit_policy.security_system_extension_success
	msg := "CIS 17.9.4: Audit Security System Extension - Success not configured"
}

system_violations contains msg if {
	not input.audit_policy.system_integrity_success
	msg := "CIS 17.9.5: Audit System Integrity - Success not configured"
}

system_violations contains msg if {
	not input.audit_policy.system_integrity_failure
	msg := "CIS 17.9.5: Audit System Integrity - Failure not configured"
}

all_violations := array.concat(
	array.concat([v | some v in account_logon_violations], [v | some v in account_management_violations]),
	array.concat(
		array.concat([v | some v in object_access_violations], [v | some v in policy_change_violations]),
		array.concat([v | some v in privilege_use_violations], [v | some v in system_violations]),
	),
)

report := {
	"compliant": compliant,
	"total_violations": count(all_violations),
	"violations": all_violations,
	"account_logon_violations": count(account_logon_violations),
	"account_management_violations": count(account_management_violations),
	"object_access_violations": count(object_access_violations),
	"policy_change_violations": count(policy_change_violations),
	"privilege_use_violations": count(privilege_use_violations),
	"system_violations": count(system_violations),
	"controls_checked": 36,
	"section": "17 Advanced Audit Policy Configuration",
	"benchmark": "CIS Windows Server 2019 v3.0.0",
}
