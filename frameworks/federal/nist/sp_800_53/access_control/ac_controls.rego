package nist.sp800_53.access_control

import rego.v1

# NIST SP 800-53 Rev 5 - Access Control (AC) Family
# Security controls for managing access to information systems

# AC-1: Access Control Policy and Procedures
access_control_policy if {
    input.ac_controls.policy.documented == true
    input.ac_controls.policy.disseminated == true
    input.ac_controls.policy.reviewed_updated == true
    input.ac_controls.procedures.implementation_documented == true
}

# AC-2: Account Management
account_management if {
    input.ac_controls.account_management.automated_tools == true
    input.ac_controls.account_management.approval_process == true
    input.ac_controls.account_management.regular_reviews == true
    input.ac_controls.account_management.timely_removal == true
}

# AC-3: Access Enforcement
access_enforcement if {
    input.ac_controls.access_enforcement.mandatory_access_control == true
    input.ac_controls.access_enforcement.discretionary_access_control == true
    input.ac_controls.access_enforcement.role_based_access_control == true
}

# AC-4: Information Flow Enforcement
information_flow_enforcement if {
    input.ac_controls.information_flow.security_labels == true
    input.ac_controls.information_flow.flow_control_policies == true
    input.ac_controls.information_flow.automated_enforcement == true
}

# AC-5: Separation of Duties
separation_of_duties if {
    input.ac_controls.separation_duties.critical_functions_divided == true
    input.ac_controls.separation_duties.documented_assignments == true
    input.ac_controls.separation_duties.monitored_compliance == true
}

# AC-6: Least Privilege
least_privilege if {
    input.ac_controls.least_privilege.minimum_access_granted == true
    input.ac_controls.least_privilege.privileged_functions_authorized == true
    input.ac_controls.least_privilege.non_privileged_access_default == true
}

# AC-7: Unsuccessful Logon Attempts
unsuccessful_logon_attempts if {
    input.ac_controls.logon_attempts.lockout_configured == true
    input.ac_controls.logon_attempts.maximum_attempts <= 5
    input.ac_controls.logon_attempts.lockout_duration >= 15
}

# AC-8: System Use Notification
system_use_notification if {
    input.ac_controls.use_notification.banner_displayed == true
    input.ac_controls.use_notification.acknowledgment_required == true
    input.ac_controls.use_notification.monitoring_consent == true
}

# AC-9: Previous Logon Notification
previous_logon_notification if {
    input.ac_controls.logon_notification.timestamp_displayed == true
    input.ac_controls.logon_notification.location_displayed == true
    input.ac_controls.logon_notification.unsuccessful_attempts_displayed == true
}

# AC-10: Concurrent Session Control
concurrent_session_control if {
    input.ac_controls.session_control.limits_configured == true
    input.ac_controls.session_control.per_account_limits == true
    input.ac_controls.session_control.per_device_limits == true
}

# AC-11: Session Lock
session_lock if {
    input.ac_controls.session_lock.inactivity_timeout <= 900  # 15 minutes
    input.ac_controls.session_lock.pattern_hiding == true
    input.ac_controls.session_lock.authentication_required == true
}

# AC-12: Session Termination
session_termination if {
    input.ac_controls.session_termination.automatic_termination == true
    input.ac_controls.session_termination.user_initiated == true
    input.ac_controls.session_termination.administrative_termination == true
}

# AC-14: Permitted Actions without Identification or Authentication
permitted_actions_restricted if {
    count(input.ac_controls.permitted_actions.unauthenticated_functions) <= 2
    every action in input.ac_controls.permitted_actions.unauthenticated_functions {
        action in ["system_status", "public_information"]
    }
}

# AC-15: Automated Marking
automated_marking if {
    input.ac_controls.automated_marking.security_labels == true
    input.ac_controls.automated_marking.classification_marking == true
    input.ac_controls.automated_marking.handling_caveats == true
}

# AC-16: Security Attributes
security_attributes if {
    input.ac_controls.security_attributes.attribute_binding == true
    input.ac_controls.security_attributes.attribute_association == true
    input.ac_controls.security_attributes.transmission_preservation == true
}

# AC-17: Remote Access
remote_access_control if {
    input.ac_controls.remote_access.authorized_only == true
    input.ac_controls.remote_access.encrypted_connections == true
    input.ac_controls.remote_access.monitored_controlled == true
}

# AC-18: Wireless Access
wireless_access_control if {
    input.ac_controls.wireless_access.authorized_only == true
    input.ac_controls.wireless_access.encrypted_authentication == true
    input.ac_controls.wireless_access.monitored_usage == true
}

# AC-19: Access Control for Mobile Devices
mobile_device_access_control if {
    input.ac_controls.mobile_devices.usage_restrictions == true
    input.ac_controls.mobile_devices.connection_requirements == true
    input.ac_controls.mobile_devices.configuration_requirements == true
}

# AC-20: Use of External Systems
external_systems_control if {
    input.ac_controls.external_systems.authorized_only == true
    input.ac_controls.external_systems.security_requirements == true
    input.ac_controls.external_systems.user_agreements == true
}

# AC-21: Information Sharing
information_sharing_control if {
    input.ac_controls.information_sharing.user_discretion_limited == true
    input.ac_controls.information_sharing.automated_guidance == true
    input.ac_controls.information_sharing.security_attributes_preserved == true
}

# AC-22: Publicly Accessible Content
publicly_accessible_content if {
    input.ac_controls.public_content.authorized_personnel_only == true
    input.ac_controls.public_content.review_process == true
    input.ac_controls.public_content.removal_procedures == true
}

# AC-23: Data Mining Protection
data_mining_protection if {
    input.ac_controls.data_mining.detection_techniques == true
    input.ac_controls.data_mining.warning_notifications == true
    input.ac_controls.data_mining.response_procedures == true
}

# AC-24: Access Control Decisions
access_control_decisions if {
    input.ac_controls.decisions.security_attributes_used == true
    input.ac_controls.decisions.consistent_enforcement == true
    input.ac_controls.decisions.documented_criteria == true
}

# AC-25: Reference Monitor
reference_monitor if {
    input.ac_controls.reference_monitor.tamper_proof == true
    input.ac_controls.reference_monitor.always_invoked == true
    input.ac_controls.reference_monitor.small_verifiable == true
}

# Aggregate NIST SP 800-53 Access Control compliance
nist_sp800_53_ac_compliant if {
    access_control_policy
    account_management
    access_enforcement
    information_flow_enforcement
    separation_of_duties
    least_privilege
    unsuccessful_logon_attempts
    system_use_notification
    previous_logon_notification
    concurrent_session_control
    session_lock
    session_termination
    permitted_actions_restricted
    automated_marking
    security_attributes
    remote_access_control
    wireless_access_control
    mobile_device_access_control
    external_systems_control
    information_sharing_control
    publicly_accessible_content
    data_mining_protection
    access_control_decisions
    reference_monitor
}

# Detailed NIST SP 800-53 Access Control compliance report
nist_sp800_53_ac_compliance := {
    "access_control_policy": access_control_policy,
    "account_management": account_management,
    "access_enforcement": access_enforcement,
    "information_flow_enforcement": information_flow_enforcement,
    "separation_of_duties": separation_of_duties,
    "least_privilege": least_privilege,
    "unsuccessful_logon_attempts": unsuccessful_logon_attempts,
    "system_use_notification": system_use_notification,
    "previous_logon_notification": previous_logon_notification,
    "concurrent_session_control": concurrent_session_control,
    "session_lock": session_lock,
    "session_termination": session_termination,
    "permitted_actions_restricted": permitted_actions_restricted,
    "automated_marking": automated_marking,
    "security_attributes": security_attributes,
    "remote_access_control": remote_access_control,
    "wireless_access_control": wireless_access_control,
    "mobile_device_access_control": mobile_device_access_control,
    "external_systems_control": external_systems_control,
    "information_sharing_control": information_sharing_control,
    "publicly_accessible_content": publicly_accessible_content,
    "data_mining_protection": data_mining_protection,
    "access_control_decisions": access_control_decisions,
    "reference_monitor": reference_monitor,
    "overall_compliant": nist_sp800_53_ac_compliant
}

# ── Violation set (for nist_800_53.main orchestrator) ─────────────────────
# Boolean rules above are kept for compatibility with existing
# comprehensive_test_suite.rego; this set turns them into the
# violation-message shape required by the framework master.

violation contains msg if {
    not access_control_policy
    msg := "NIST AC-1: Access control policy/procedures not documented, disseminated, or reviewed"
}

violation contains msg if {
    not account_management
    msg := "NIST AC-2: Account management lacks automated tooling, approval, reviews, or timely removal"
}

violation contains msg if {
    not access_enforcement
    msg := "NIST AC-3: Access enforcement does not implement MAC, DAC, and RBAC"
}

violation contains msg if {
    not information_flow_enforcement
    msg := "NIST AC-4: Information flow enforcement lacks security labels or automated flow control"
}

violation contains msg if {
    not separation_of_duties
    msg := "NIST AC-5: Separation of duties not implemented for critical functions"
}

violation contains msg if {
    not least_privilege
    msg := "NIST AC-6: Least privilege not enforced for privileged or non-privileged access"
}

violation contains msg if {
    not unsuccessful_logon_attempts
    msg := "NIST AC-7: Logon attempts not lockout-controlled (max 5 attempts, 15-min lockout)"
}

violation contains msg if {
    not system_use_notification
    msg := "NIST AC-8: System use notification banner/acknowledgment/consent missing"
}

violation contains msg if {
    not previous_logon_notification
    msg := "NIST AC-9: Previous logon notification not displayed to users"
}

violation contains msg if {
    not concurrent_session_control
    msg := "NIST AC-10: Concurrent session limits not configured"
}

violation contains msg if {
    not session_lock
    msg := "NIST AC-11: Session lock missing (inactivity timeout ≤15 min + pattern hiding required)"
}

violation contains msg if {
    not session_termination
    msg := "NIST AC-12: Session termination (automatic/user-initiated/admin) not supported"
}

violation contains msg if {
    not permitted_actions_restricted
    msg := "NIST AC-14: Permitted unauthenticated actions exceed approved list"
}

violation contains msg if {
    not remote_access_control
    msg := "NIST AC-17: Remote access not authorized/encrypted/monitored"
}

violation contains msg if {
    not wireless_access_control
    msg := "NIST AC-18: Wireless access not authorized/encrypted/monitored"
}

violation contains msg if {
    not mobile_device_access_control
    msg := "NIST AC-19: Mobile device access control missing usage restrictions or config requirements"
}

violation contains msg if {
    not external_systems_control
    msg := "NIST AC-20: External system use not authorized or governed by user agreements"
}

violation contains msg if {
    not publicly_accessible_content
    msg := "NIST AC-22: Publicly accessible content lacks review/removal process"
}

default compliant := false

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "AC",
    "name":   "Access Control",
    "controls_evaluated": 18,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}