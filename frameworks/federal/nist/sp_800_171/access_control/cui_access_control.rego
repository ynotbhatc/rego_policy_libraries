package nist.sp800_171.access_control

import rego.v1

# NIST SP 800-171 Rev 3 - Access Control Requirements
# Protecting Controlled Unclassified Information (CUI)

# 3.1.1: Limit system access to authorized users, processes acting on behalf of authorized users, and devices
authorized_access_only if {
    input.cui_access.user_authorization.all_users_authorized == true
    input.cui_access.user_authorization.process_authorization == true
    input.cui_access.user_authorization.device_authorization == true
}

# 3.1.2: Limit system access to the types of transactions and functions that authorized users are permitted to execute
transaction_function_limits if {
    input.cui_access.transaction_limits.role_based_restrictions == true
    input.cui_access.transaction_limits.function_authorization == true
    input.cui_access.transaction_limits.documented_permissions == true
}

# 3.1.3: Control the flow of CUI in accordance with approved authorizations
cui_flow_control if {
    input.cui_access.flow_control.approved_authorizations == true
    input.cui_access.flow_control.automated_enforcement == true
    input.cui_access.flow_control.monitoring_implemented == true
}

# 3.1.4: Separate the duties of individuals to reduce the risk of malevolent activity without collusion
duty_separation if {
    input.cui_access.separation_duties.critical_functions_separated == true
    input.cui_access.separation_duties.documented_assignments == true
    input.cui_access.separation_duties.collusion_prevention == true
}

# 3.1.5: Employ the principle of least privilege, including for specific security functions and privileged accounts
least_privilege_implementation if {
    input.cui_access.least_privilege.minimum_necessary_access == true
    input.cui_access.least_privilege.privileged_account_restrictions == true
    input.cui_access.least_privilege.security_function_limits == true
}

# 3.1.6: Use non-privileged accounts or roles when accessing nonsecurity functions
non_privileged_access if {
    input.cui_access.non_privileged.separate_accounts == true
    input.cui_access.non_privileged.role_segregation == true
    input.cui_access.non_privileged.privilege_escalation_controlled == true
}

# 3.1.7: Prevent non-privileged users from executing privileged functions
privileged_function_prevention if {
    input.cui_access.privileged_prevention.execution_controls == true
    input.cui_access.privileged_prevention.authorization_required == true
    input.cui_access.privileged_prevention.monitoring_implemented == true
}

# 3.1.8: Limit unsuccessful logon attempts
logon_attempt_limits if {
    input.cui_access.logon_limits.maximum_attempts <= 3
    input.cui_access.logon_limits.lockout_implemented == true
    input.cui_access.logon_limits.lockout_duration >= 15
}

# 3.1.9: Provide privacy and security notices consistent with applicable CUI rules
privacy_security_notices if {
    input.cui_access.notices.privacy_notice_displayed == true
    input.cui_access.notices.security_notice_displayed == true
    input.cui_access.notices.cui_rules_referenced == true
}

# 3.1.10: Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity
session_lock_implementation if {
    input.cui_access.session_lock.inactivity_timeout <= 900  # 15 minutes
    input.cui_access.session_lock.pattern_hiding == true
    input.cui_access.session_lock.authentication_required == true
}

# 3.1.11: Terminate (automatically) a user session after a defined condition
session_termination if {
    input.cui_access.session_termination.defined_conditions == true
    input.cui_access.session_termination.automatic_termination == true
    input.cui_access.session_termination.user_notification == true
}

# 3.1.12: Monitor and control remote access sessions
remote_access_monitoring if {
    input.cui_access.remote_access.session_monitoring == true
    input.cui_access.remote_access.access_control == true
    input.cui_access.remote_access.encrypted_connections == true
}

# 3.1.13: Employ cryptographic mechanisms to protect the confidentiality of remote access sessions
remote_access_encryption if {
    input.cui_access.remote_encryption.cryptographic_protection == true
    input.cui_access.remote_encryption.approved_algorithms == true
    input.cui_access.remote_encryption.end_to_end_encryption == true
}

# 3.1.14: Route remote access via managed access control points
managed_access_control_points if {
    input.cui_access.managed_access.designated_control_points == true
    input.cui_access.managed_access.centralized_management == true
    input.cui_access.managed_access.monitoring_capability == true
}

# 3.1.15: Authorize remote execution of privileged commands and remote access to security-relevant information
authorized_remote_privileged_access if {
    input.cui_access.remote_privileged.explicit_authorization == true
    input.cui_access.remote_privileged.strong_authentication == true
    input.cui_access.remote_privileged.logging_monitoring == true
}

# 3.1.16: Authorize wireless access prior to allowing such connections
wireless_access_authorization if {
    input.cui_access.wireless.pre_authorization_required == true
    input.cui_access.wireless.configuration_management == true
    input.cui_access.wireless.security_controls == true
}

# 3.1.17: Protect wireless access using authentication and encryption
wireless_protection if {
    input.cui_access.wireless_protection.authentication_required == true
    input.cui_access.wireless_protection.encryption_implemented == true
    input.cui_access.wireless_protection.approved_protocols == true
}

# 3.1.18: Control connection of mobile devices
mobile_device_control if {
    input.cui_access.mobile_devices.connection_controls == true
    input.cui_access.mobile_devices.device_registration == true
    input.cui_access.mobile_devices.security_requirements == true
}

# 3.1.19: Encrypt CUI on mobile devices and mobile computing platforms
mobile_device_encryption if {
    input.cui_access.mobile_encryption.cui_encrypted == true
    input.cui_access.mobile_encryption.approved_encryption == true
    input.cui_access.mobile_encryption.key_management == true
}

# 3.1.20: Verify and control/limit connections to and use of external systems
external_system_control if {
    input.cui_access.external_systems.connection_verification == true
    input.cui_access.external_systems.usage_limitations == true
    input.cui_access.external_systems.security_assessments == true
}

# 3.1.21: Limit use of organizational portable storage devices on external systems
portable_storage_limits if {
    input.cui_access.portable_storage.usage_restrictions == true
    input.cui_access.portable_storage.authorization_required == true
    input.cui_access.portable_storage.security_controls == true
}

# 3.1.22: Control CUI posted or processed on publicly accessible systems
public_system_cui_control if {
    input.cui_access.public_systems.cui_restrictions == true
    input.cui_access.public_systems.review_procedures == true
    input.cui_access.public_systems.removal_capability == true
}

# Aggregate NIST SP 800-171 Access Control compliance
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
    "overall_compliant": nist_sp800_171_ac_compliant
}