package iso27001.access_control

import rego.v1

# ISO 27001:2022 - A.9 Access Control
# Technical controls for managing access to information and information processing facilities

# A.9.1 - Business requirements for access control
business_requirements_met if {
    input.access_control.policy.documented == true
    input.access_control.policy.approved == true
    input.access_control.policy.communicated == true
    input.access_control.access_rules.defined == true
    input.access_control.access_rules.enforced == true
}

# A.9.2 - User access management
user_access_management if {
    # A.9.2.1 - User registration and de-registration
    user_registration_process
    
    # A.9.2.2 - User access provisioning
    user_access_provisioning
    
    # A.9.2.3 - Management of privileged access rights
    privileged_access_management
    
    # A.9.2.4 - Management of secret authentication information
    secret_authentication_management
    
    # A.9.2.5 - Review of user access rights
    access_rights_review
    
    # A.9.2.6 - Removal or adjustment of access rights
    access_rights_removal
}

# A.9.2.1 - User registration and de-registration process
user_registration_process if {
    input.user_management.registration.formal_process == true
    input.user_management.registration.authorization_required == true
    input.user_management.registration.documented == true
    count(input.user_management.unauthorized_users) == 0
}

# A.9.2.2 - User access provisioning
user_access_provisioning if {
    input.user_management.provisioning.least_privilege == true
    input.user_management.provisioning.role_based == true
    input.user_management.provisioning.approval_required == true
    input.user_management.provisioning.automated_tools == true
}

# A.9.2.3 - Management of privileged access rights
privileged_access_management if {
    input.privileged_access.allocation_restricted == true
    input.privileged_access.regular_review == true
    input.privileged_access.monitoring_enabled == true
    input.privileged_access.multi_factor_auth == true
    count(input.privileged_access.shared_accounts) == 0
}

# A.9.2.4 - Management of secret authentication information
secret_authentication_management if {
    # Password policy enforcement
    password_policy_compliant
    
    # Multi-factor authentication
    mfa_implemented
    
    # Secret storage and handling
    secret_handling_secure
}

password_policy_compliant if {
    input.authentication.password_policy.min_length >= 8
    input.authentication.password_policy.complexity_required == true
    input.authentication.password_policy.expiry_enabled == true
    input.authentication.password_policy.history_count >= 12
    input.authentication.password_policy.lockout_enabled == true
}

mfa_implemented if {
    input.authentication.mfa.enabled == true
    input.authentication.mfa.required_for_admin == true
    input.authentication.mfa.required_for_remote == true
}

secret_handling_secure if {
    input.authentication.secrets.encrypted_storage == true
    input.authentication.secrets.access_controlled == true
    input.authentication.secrets.regular_rotation == true
    input.authentication.secrets.secure_transmission == true
}

# A.9.2.5 - Review of user access rights
access_rights_review if {
    input.access_review.regular_schedule == true
    input.access_review.management_approval == true
    input.access_review.documented_results == true
    input.access_review.remediation_tracked == true
    # Reviews should be at least quarterly
    input.access_review.frequency_days <= 120
}

# A.9.2.6 - Removal or adjustment of access rights
access_rights_removal if {
    input.access_removal.immediate_termination == true
    input.access_removal.role_change_adjustment == true
    input.access_removal.automated_process == true
    input.access_removal.verification_required == true
}

# A.9.3 - User responsibilities
user_responsibilities if {
    input.user_responsibilities.password_protection == true
    input.user_responsibilities.unattended_sessions == true
    input.user_responsibilities.clear_desk_policy == true
    input.user_responsibilities.training_completed == true
}

# A.9.4 - System and application access control
system_application_access_control if {
    # A.9.4.1 - Information access restriction
    information_access_restriction
    
    # A.9.4.2 - Secure log-on procedures
    secure_logon_procedures
    
    # A.9.4.3 - Password management system
    password_management_system
    
    # A.9.4.4 - Use of privileged utility programs
    privileged_utility_control
    
    # A.9.4.5 - Access control to program source code
    source_code_access_control
}

# A.9.4.1 - Information access restriction
information_access_restriction if {
    input.system_access.need_to_know == true
    input.system_access.role_based_control == true
    input.system_access.data_classification_enforced == true
    input.system_access.segregation_of_duties == true
}

# A.9.4.2 - Secure log-on procedures
secure_logon_procedures if {
    input.logon.user_identification_required == true
    input.logon.authentication_required == true
    input.logon.session_timeout_configured == true
    input.logon.failed_attempt_lockout == true
    input.logon.warning_message_displayed == true
    
    # Session timeout should be reasonable (max 30 minutes)
    input.logon.session_timeout_minutes <= 30
    
    # Failed attempt lockout should be strict
    input.logon.max_failed_attempts <= 5
}

# A.9.4.3 - Password management system
password_management_system if {
    input.password_system.centralized_management == true
    input.password_system.policy_enforcement == true
    input.password_system.secure_storage == true
    input.password_system.change_notification == true
    input.password_system.temporary_passwords_controlled == true
}

# A.9.4.4 - Use of privileged utility programs
privileged_utility_control if {
    input.privileged_utilities.restricted_access == true
    input.privileged_utilities.logging_enabled == true
    input.privileged_utilities.approval_required == true
    input.privileged_utilities.monitoring_active == true
}

# A.9.4.5 - Access control to program source code
source_code_access_control if {
    input.source_code.version_control == true
    input.source_code.access_restricted == true
    input.source_code.change_approval == true
    input.source_code.backup_protected == true
    input.source_code.audit_trail == true
}

# Overall access control compliance
compliant if {
    business_requirements_met
    user_access_management
    user_responsibilities
    system_application_access_control
}

# Detailed compliance reporting
compliance_details := {
    "business_requirements": business_requirements_met,
    "user_access_management": {
        "user_registration": user_registration_process,
        "access_provisioning": user_access_provisioning,
        "privileged_access": privileged_access_management,
        "secret_management": secret_authentication_management,
        "access_review": access_rights_review,
        "access_removal": access_rights_removal
    },
    "user_responsibilities": user_responsibilities,
    "system_application_access": {
        "information_restriction": information_access_restriction,
        "secure_logon": secure_logon_procedures,
        "password_management": password_management_system,
        "privileged_utilities": privileged_utility_control,
        "source_code_access": source_code_access_control
    },
    "overall_compliant": compliant
}