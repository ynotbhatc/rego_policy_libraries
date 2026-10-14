# METADATA
# title: "NIST SP 800-171 Rev 3 - Access Control Requirements"
# custom:
#   class: compliance
#   framework: nist_sp_800_171
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 64
#     cited: 16
#     expected: 16
#     found: 64
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_171.access_control

import rego.v1

# NIST SP 800-171 Rev 3 - Access Control Requirements
#
# Ids are NIST SP 800-171 Rev 3 element identifiers from the NIST CPRT export
# (https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all, sha256 19d18ef88700e468..., retrieved 2026-10-13).
# The fact checks below were written against the Rev 2 statements; each is re-keyed to the Rev 3
# requirement that carries its Rev 2 slot. A Rev 2 slot withdrawn in Rev 3 with "Incorporated into"
# is keyed to the incorporating requirement(s); one withdrawn as "Addressed by", recategorized as
# NCO, technology-specific or for consistency with SP 800-53 is retired: its rule is kept for lineage
# but it emits no violation and is not a Rev 3 control. Rev 3 status per requirement (attestation
# plus these facts) is computed by nist_800_171_main.rego (package nist_800_171.main).
# Protecting Controlled Unclassified Information (CUI)

# 03.01.01 Account Management (Rev 2 3.1.1): Limit system access to authorized users, processes acting on behalf of authorized users, and devices
default authorized_access_only := false

authorized_access_only if {
	input.cui_access.user_authorization.all_users_authorized == true
	input.cui_access.user_authorization.process_authorization == true
	input.cui_access.user_authorization.device_authorization == true
}

# 03.01.02 Access Enforcement (Rev 2 3.1.2): Limit system access to the types of transactions and functions that authorized users are permitted to execute
default transaction_function_limits := false

transaction_function_limits if {
	input.cui_access.transaction_limits.role_based_restrictions == true
	input.cui_access.transaction_limits.function_authorization == true
	input.cui_access.transaction_limits.documented_permissions == true
}

# 03.01.03 Information Flow Enforcement (Rev 2 3.1.3): Control the flow of CUI in accordance with approved authorizations
default cui_flow_control := false

cui_flow_control if {
	input.cui_access.flow_control.approved_authorizations == true
	input.cui_access.flow_control.automated_enforcement == true
	input.cui_access.flow_control.monitoring_implemented == true
}

# 03.01.04 Separation of Duties (Rev 2 3.1.4): Separate the duties of individuals to reduce the risk of malevolent activity without collusion
default duty_separation := false

duty_separation if {
	input.cui_access.separation_duties.critical_functions_separated == true
	input.cui_access.separation_duties.documented_assignments == true
	input.cui_access.separation_duties.collusion_prevention == true
}

# 03.01.05 Least Privilege (Rev 2 3.1.5): Employ the principle of least privilege, including for specific security functions and privileged accounts
default least_privilege_implementation := false

least_privilege_implementation if {
	input.cui_access.least_privilege.minimum_necessary_access == true
	input.cui_access.least_privilege.privileged_account_restrictions == true
	input.cui_access.least_privilege.security_function_limits == true
}

# 03.01.06 Least Privilege – Privileged Accounts (Rev 2 3.1.6): Use non-privileged accounts or roles when accessing nonsecurity functions
default non_privileged_access := false

non_privileged_access if {
	input.cui_access.non_privileged.separate_accounts == true
	input.cui_access.non_privileged.role_segregation == true
	input.cui_access.non_privileged.privilege_escalation_controlled == true
}

# 03.01.07 Least Privilege – Privileged Functions (Rev 2 3.1.7): Prevent non-privileged users from executing privileged functions
default privileged_function_prevention := false

privileged_function_prevention if {
	input.cui_access.privileged_prevention.execution_controls == true
	input.cui_access.privileged_prevention.authorization_required == true
	input.cui_access.privileged_prevention.monitoring_implemented == true
}

# 03.01.08 Unsuccessful Logon Attempts (Rev 2 3.1.8): Limit unsuccessful logon attempts
default logon_attempt_limits := false

logon_attempt_limits if {
	input.cui_access.logon_limits.maximum_attempts <= 3
	input.cui_access.logon_limits.lockout_implemented == true
	input.cui_access.logon_limits.lockout_duration >= 15
}

# 03.01.09 System Use Notification (Rev 2 3.1.9): Provide privacy and security notices consistent with applicable CUI rules
default privacy_security_notices := false

privacy_security_notices if {
	input.cui_access.notices.privacy_notice_displayed == true
	input.cui_access.notices.security_notice_displayed == true
	input.cui_access.notices.cui_rules_referenced == true
}

# 03.01.10 Device Lock (Rev 2 3.1.10): Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity
default session_lock_implementation := false

session_lock_implementation if {
	input.cui_access.session_lock.inactivity_timeout <= 900 # 15 minutes
	input.cui_access.session_lock.pattern_hiding == true
	input.cui_access.session_lock.authentication_required == true
}

# 03.01.11 Session Termination (Rev 2 3.1.11): Terminate (automatically) a user session after a defined condition
default session_termination := false

session_termination if {
	input.cui_access.session_termination.defined_conditions == true
	input.cui_access.session_termination.automatic_termination == true
	input.cui_access.session_termination.user_notification == true
}

# 03.01.12 Remote Access (Rev 2 3.1.12): Monitor and control remote access sessions
default remote_access_monitoring := false

remote_access_monitoring if {
	input.cui_access.remote_access.session_monitoring == true
	input.cui_access.remote_access.access_control == true
	input.cui_access.remote_access.encrypted_connections == true
}

# RETIRED, not a Rev 3 control (Rev 2 3.1.13, withdrawn in Rev 3: Addressed by 03.13.08.): Employ cryptographic mechanisms to protect the confidentiality of remote access sessions
default remote_access_encryption := false

remote_access_encryption if {
	input.cui_access.remote_encryption.cryptographic_protection == true
	input.cui_access.remote_encryption.approved_algorithms == true
	input.cui_access.remote_encryption.end_to_end_encryption == true
}

# 03.01.12 (Rev 2 3.1.14, withdrawn in Rev 3: Incorporated into 03.01.12.): Route remote access via managed access control points
default managed_access_control_points := false

managed_access_control_points if {
	input.cui_access.managed_access.designated_control_points == true
	input.cui_access.managed_access.centralized_management == true
	input.cui_access.managed_access.monitoring_capability == true
}

# 03.01.12 (Rev 2 3.1.15, withdrawn in Rev 3: Incorporated into 03.01.12.): Authorize remote execution of privileged commands and remote access to security-relevant information
default authorized_remote_privileged_access := false

authorized_remote_privileged_access if {
	input.cui_access.remote_privileged.explicit_authorization == true
	input.cui_access.remote_privileged.strong_authentication == true
	input.cui_access.remote_privileged.logging_monitoring == true
}

# 03.01.16 Wireless Access (Rev 2 3.1.16): Authorize wireless access prior to allowing such connections
default wireless_access_authorization := false

wireless_access_authorization if {
	input.cui_access.wireless.pre_authorization_required == true
	input.cui_access.wireless.configuration_management == true
	input.cui_access.wireless.security_controls == true
}

# 03.01.16 (Rev 2 3.1.17, withdrawn in Rev 3: Incorporated into 03.01.16.): Protect wireless access using authentication and encryption
default wireless_protection := false

wireless_protection if {
	input.cui_access.wireless_protection.authentication_required == true
	input.cui_access.wireless_protection.encryption_implemented == true
	input.cui_access.wireless_protection.approved_protocols == true
}

# 03.01.18 Access Control for Mobile Devices (Rev 2 3.1.18): Control connection of mobile devices
default mobile_device_control := false

mobile_device_control if {
	input.cui_access.mobile_devices.connection_controls == true
	input.cui_access.mobile_devices.device_registration == true
	input.cui_access.mobile_devices.security_requirements == true
}

# 03.01.18 (Rev 2 3.1.19, withdrawn in Rev 3: Incorporated into 03.01.18.): Encrypt CUI on mobile devices and mobile computing platforms
default mobile_device_encryption := false

mobile_device_encryption if {
	input.cui_access.mobile_encryption.cui_encrypted == true
	input.cui_access.mobile_encryption.approved_encryption == true
	input.cui_access.mobile_encryption.key_management == true
}

# 03.01.20 Use of External Systems (Rev 2 3.1.20): Verify and control/limit connections to and use of external systems
default external_system_control := false

external_system_control if {
	input.cui_access.external_systems.connection_verification == true
	input.cui_access.external_systems.usage_limitations == true
	input.cui_access.external_systems.security_assessments == true
}

# 03.01.20 (Rev 2 3.1.21, withdrawn in Rev 3: Incorporated into 03.01.20.): Limit use of organizational portable storage devices on external systems
default portable_storage_limits := false

portable_storage_limits if {
	input.cui_access.portable_storage.usage_restrictions == true
	input.cui_access.portable_storage.authorization_required == true
	input.cui_access.portable_storage.security_controls == true
}

# 03.01.22 Publicly Accessible Content (Rev 2 3.1.22): Control CUI posted or processed on publicly accessible systems
default public_system_cui_control := false

public_system_cui_control if {
	input.cui_access.public_systems.cui_restrictions == true
	input.cui_access.public_systems.review_procedures == true
	input.cui_access.public_systems.removal_capability == true
}

# Legacy Rev 2-shaped aggregate (all 22 Rev 2 rules, including the retired 3.1.13), kept for
# existing consumers. Rev 3 status: `compliant` / `compliance_report` below and nist_800_171.main.
default nist_sp800_171_ac_compliant := false

nist_sp800_171_ac_compliant if {
	authorized_access_only
	transaction_function_limits
	cui_flow_control
	duty_separation
	least_privilege_implementation
	non_privileged_access
	privileged_function_prevention
	logon_attempt_limits
	privacy_security_notices
	session_lock_implementation
	session_termination
	remote_access_monitoring
	remote_access_encryption
	managed_access_control_points
	authorized_remote_privileged_access
	wireless_access_authorization
	wireless_protection
	mobile_device_control
	mobile_device_encryption
	external_system_control
	portable_storage_limits
	public_system_cui_control
}

# Detailed NIST SP 800-171 Access Control compliance report
nist_sp800_171_ac_compliance := {
	"authorized_access_only": authorized_access_only,
	"transaction_function_limits": transaction_function_limits,
	"cui_flow_control": cui_flow_control,
	"duty_separation": duty_separation,
	"least_privilege_implementation": least_privilege_implementation,
	"non_privileged_access": non_privileged_access,
	"privileged_function_prevention": privileged_function_prevention,
	"logon_attempt_limits": logon_attempt_limits,
	"privacy_security_notices": privacy_security_notices,
	"session_lock_implementation": session_lock_implementation,
	"session_termination": session_termination,
	"remote_access_monitoring": remote_access_monitoring,
	"remote_access_encryption": remote_access_encryption,
	"managed_access_control_points": managed_access_control_points,
	"authorized_remote_privileged_access": authorized_remote_privileged_access,
	"wireless_access_authorization": wireless_access_authorization,
	"wireless_protection": wireless_protection,
	"mobile_device_control": mobile_device_control,
	"mobile_device_encryption": mobile_device_encryption,
	"external_system_control": external_system_control,
	"portable_storage_limits": portable_storage_limits,
	"public_system_cui_control": public_system_cui_control,
	"overall_compliant": nist_sp800_171_ac_compliant,
}

# Violations — one per fact check, keyed to its Rev 3 requirement (retired checks emit none)

violations contains msg if {
	not authorized_access_only
	msg := "NIST SP 800-171 03.01.01: fact check failed — Limit system access to authorized users, processes acting on behalf of authorized users, and devices"
}

violations contains msg if {
	not transaction_function_limits
	msg := "NIST SP 800-171 03.01.02: fact check failed — Limit system access to the types of transactions and functions that authorized users are permitted to execute"
}

violations contains msg if {
	not cui_flow_control
	msg := "NIST SP 800-171 03.01.03: fact check failed — Control the flow of CUI in accordance with approved authorizations"
}

violations contains msg if {
	not duty_separation
	msg := "NIST SP 800-171 03.01.04: fact check failed — Separate the duties of individuals to reduce the risk of malevolent activity without collusion"
}

violations contains msg if {
	not least_privilege_implementation
	msg := "NIST SP 800-171 03.01.05: fact check failed — Employ the principle of least privilege, including for specific security functions and privileged accounts"
}

violations contains msg if {
	not non_privileged_access
	msg := "NIST SP 800-171 03.01.06: fact check failed — Use non-privileged accounts or roles when accessing nonsecurity functions"
}

violations contains msg if {
	not privileged_function_prevention
	msg := "NIST SP 800-171 03.01.07: fact check failed — Prevent non-privileged users from executing privileged functions"
}

violations contains msg if {
	not logon_attempt_limits
	msg := "NIST SP 800-171 03.01.08: fact check failed — Limit unsuccessful logon attempts"
}

violations contains msg if {
	not privacy_security_notices
	msg := "NIST SP 800-171 03.01.09: fact check failed — Provide privacy and security notices consistent with applicable CUI rules"
}

violations contains msg if {
	not session_lock_implementation
	msg := "NIST SP 800-171 03.01.10: fact check failed — Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity"
}

violations contains msg if {
	not session_termination
	msg := "NIST SP 800-171 03.01.11: fact check failed — Terminate (automatically) a user session after a defined condition"
}

violations contains msg if {
	not remote_access_monitoring
	msg := "NIST SP 800-171 03.01.12: fact check failed — Monitor and control remote access sessions"
}

violations contains msg if {
	not managed_access_control_points
	msg := "NIST SP 800-171 03.01.12 (Rev 2 3.1.14, withdrawn in Rev 3: Incorporated into 03.01.12.): fact check failed — Route remote access via managed access control points"
}

violations contains msg if {
	not authorized_remote_privileged_access
	msg := "NIST SP 800-171 03.01.12 (Rev 2 3.1.15, withdrawn in Rev 3: Incorporated into 03.01.12.): fact check failed — Authorize remote execution of privileged commands and remote access to security-relevant information"
}

violations contains msg if {
	not wireless_access_authorization
	msg := "NIST SP 800-171 03.01.16: fact check failed — Authorize wireless access prior to allowing such connections"
}

violations contains msg if {
	not wireless_protection
	msg := "NIST SP 800-171 03.01.16 (Rev 2 3.1.17, withdrawn in Rev 3: Incorporated into 03.01.16.): fact check failed — Protect wireless access using authentication and encryption"
}

violations contains msg if {
	not mobile_device_control
	msg := "NIST SP 800-171 03.01.18: fact check failed — Control connection of mobile devices"
}

violations contains msg if {
	not mobile_device_encryption
	msg := "NIST SP 800-171 03.01.18 (Rev 2 3.1.19, withdrawn in Rev 3: Incorporated into 03.01.18.): fact check failed — Encrypt CUI on mobile devices and mobile computing platforms"
}

violations contains msg if {
	not external_system_control
	msg := "NIST SP 800-171 03.01.20: fact check failed — Verify and control/limit connections to and use of external systems"
}

violations contains msg if {
	not portable_storage_limits
	msg := "NIST SP 800-171 03.01.20 (Rev 2 3.1.21, withdrawn in Rev 3: Incorporated into 03.01.20.): fact check failed — Limit use of organizational portable storage devices on external systems"
}

violations contains msg if {
	not public_system_cui_control
	msg := "NIST SP 800-171 03.01.22: fact check failed — Control CUI posted or processed on publicly accessible systems"
}

default compliant := false

compliant if count(violations) == 0

compliance_report := {
	"family": "03.01 Access Control",
	"standard": "NIST SP 800-171 Rev 3",
	"total_controls": 16,
	"violations": violations,
	"compliant": compliant,
	"retired_rev2_checks": {"rev2_3.1.13_remote_access_encryption": remote_access_encryption},
	"controls": {
		"03.01.01_authorized_access_only": authorized_access_only,
		"03.01.02_transaction_function_limits": transaction_function_limits,
		"03.01.03_cui_flow_control": cui_flow_control,
		"03.01.04_duty_separation": duty_separation,
		"03.01.05_least_privilege_implementation": least_privilege_implementation,
		"03.01.06_non_privileged_access": non_privileged_access,
		"03.01.07_privileged_function_prevention": privileged_function_prevention,
		"03.01.08_logon_attempt_limits": logon_attempt_limits,
		"03.01.09_privacy_security_notices": privacy_security_notices,
		"03.01.10_session_lock_implementation": session_lock_implementation,
		"03.01.11_session_termination": session_termination,
		"03.01.12_remote_access_monitoring": remote_access_monitoring,
		"03.01.12_managed_access_control_points": managed_access_control_points,
		"03.01.12_authorized_remote_privileged_access": authorized_remote_privileged_access,
		"03.01.16_wireless_access_authorization": wireless_access_authorization,
		"03.01.16_wireless_protection": wireless_protection,
		"03.01.18_mobile_device_control": mobile_device_control,
		"03.01.18_mobile_device_encryption": mobile_device_encryption,
		"03.01.20_external_system_control": external_system_control,
		"03.01.20_portable_storage_limits": portable_storage_limits,
		"03.01.22_public_system_cui_control": public_system_cui_control,
	},
}
