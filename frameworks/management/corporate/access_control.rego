package corporate.access.control

import rego.v1

# Corporate Access Control and Identity Management Policy
# Implements Role-Based Access Control (RBAC), Privileged Access Management (PAM),
# and Segregation of Duties (SoD) controls

# Main access control compliance evaluation
access_control_compliant if {
    rbac_implemented
    privileged_access_managed
    segregation_of_duties_enforced
    account_lifecycle_managed
    access_monitoring_enabled
    mfa_requirements_met
}

# Role-Based Access Control (RBAC) Implementation
# Corporate Policy: "All access must be based on business need and least privilege"
rbac_implemented if {
    all_users_have_roles
    roles_follow_least_privilege
    role_definitions_documented
    role_assignments_justified
}

all_users_have_roles if {
    users_without_roles := [user |
        user = input.users[_]
        user.status == "active"
        count(user.roles) == 0
    ]
    count(users_without_roles) == 0
}

roles_follow_least_privilege if {
    # No user should have more permissions than necessary for their job function
    violations := [user |
        user = input.users[_]
        user.status == "active"
        excessive_permissions(user)
    ]
    count(violations) == 0
}

excessive_permissions(user) if {
    # User has roles that conflict with their job function
    user_job_function := user.job_function
    inappropriate_roles := [role |
        role = user.roles[_]
        not role_appropriate_for_job_function(role.name, user_job_function)
    ]
    count(inappropriate_roles) > 0
}

role_appropriate_for_job_function(role, "developer") if {
    role in allowed_developer_roles
}

role_appropriate_for_job_function(role, "qa_analyst") if {
    role in allowed_qa_roles
}

role_appropriate_for_job_function(role, "business_analyst") if {
    role in allowed_business_roles
}

role_appropriate_for_job_function(role, "manager") if {
    role in allowed_manager_roles
}

role_appropriate_for_job_function(role, "admin") if {
    role in allowed_admin_roles
}

role_appropriate_for_job_function(role, "auditor") if {
    role in allowed_auditor_roles
}

allowed_developer_roles := {
    "developer", "dev_read", "dev_write", "code_reviewer", 
    "development_environment_access", "version_control_user"
}

allowed_qa_roles := {
    "qa_analyst", "test_environment_access", "qa_read", "qa_write",
    "test_execution", "defect_management"
}

allowed_business_roles := {
    "business_user", "report_viewer", "application_user", 
    "read_only_access", "business_application_access"
}

allowed_manager_roles := {
    "manager", "approver", "report_viewer", "business_user",
    "team_lead", "project_manager", "budget_approver"
}

allowed_admin_roles := {
    "system_admin", "database_admin", "network_admin", "security_admin",
    "application_admin", "infrastructure_admin", "backup_admin"
}

allowed_auditor_roles := {
    "auditor", "compliance_reviewer", "read_only_admin", "audit_log_viewer",
    "compliance_reporter", "risk_assessor"
}

role_definitions_documented if {
    undefined_roles := [role |
        user = input.users[_]
        role = user.roles[_]
        not role_definition_exists(role.name)
    ]
    count(undefined_roles) == 0
}

role_definition_exists(role_name) if {
    input.role_definitions[role_name]
}

role_assignments_justified if {
    # All role assignments must have business justification
    unjustified_assignments := [assignment |
        user = input.users[_]
        role = user.roles[_]
        not role_assignment_justified(user, role)
        assignment := {"user": user.id, "role": role.name}
    ]
    count(unjustified_assignments) == 0
}

role_assignment_justified(user, role) if {
    role.business_justification
    role.approved_by
    role.approval_date
    # Calculate days since approval using nanosecond timestamps
    approval_age_days := (time.now_ns() - role.approval_date) / (24 * 60 * 60 * 1000000000)
    approval_age_days <= max_approval_age_days(role.risk_level)
}

max_approval_age_days("high") := 90     # High-risk roles need recent approval
max_approval_age_days("medium") := 180  # Medium-risk roles
max_approval_age_days("low") := 365     # Low-risk roles

# Privileged Access Management (PAM)
# Corporate Policy: "Privileged access requires enhanced controls and monitoring"
privileged_access_managed if {
    privileged_accounts_identified
    privileged_access_controls_enforced
    privileged_sessions_monitored
    emergency_access_controlled
}

privileged_accounts_identified if {
    # All privileged accounts must be properly classified
    unclassified_privileged := [user |
        user = input.users[_]
        user_has_privileged_access(user)
        not user.privileged_account_classification
    ]
    count(unclassified_privileged) == 0
}

user_has_privileged_access(user) if {
    some role in user.roles
    role.name in privileged_roles
}

privileged_roles := {
    "system_admin", "database_admin", "security_admin", "network_admin",
    "application_admin", "root", "administrator", "domain_admin",
    "service_account_admin", "backup_admin", "audit_admin"
}

privileged_access_controls_enforced if {
    # Privileged accounts must have enhanced controls
    violations := [user |
        user = input.users[_]
        user_has_privileged_access(user)
        not privileged_controls_adequate(user)
    ]
    count(violations) == 0
}

privileged_controls_adequate(user) if {
    user.mfa_enabled == true
    user.session_recording == true
    user.access_approval_workflow == true
    user.privileged_access_review_frequency <= 30  # 30 days
    user.just_in_time_access == true
}

privileged_sessions_monitored if {
    # All privileged sessions must be monitored and recorded
    violations := [session |
        session = input.active_sessions[_]
        session_is_privileged(session)
        not session_monitoring_adequate(session)
    ]
    count(violations) == 0
}

session_is_privileged(session) if {
    user := input.users[session.user_id]
    user_has_privileged_access(user)
}

session_monitoring_adequate(session) if {
    session.monitoring.enabled == true
    session.monitoring.recording == true
    session.monitoring.real_time_alerts == true
    session.monitoring.activity_logging == true
}

emergency_access_controlled if {
    # Emergency access procedures must be documented and controlled
    every access in input.emergency_access {
        emergency_access_valid(access)
    }
}

emergency_access_valid(access) if {
    access.incident_number
    access.business_justification
    access.approver
    access.time_limited == true
    access.monitoring_enabled == true
    emergency_access_not_expired(access)
}

emergency_access_not_expired(access) if {
    expiration_ns := time.parse_rfc3339_ns(access.expiration_time)
    expiration_ns > time.now_ns()
}

# Segregation of Duties (SoD)
# Corporate Policy: "Critical business processes must have segregation of duties"
segregation_of_duties_enforced if {
    conflicting_roles_prevented
    financial_process_separation
    it_process_separation
    approval_workflow_separation
}

conflicting_roles_prevented if {
    # Users cannot have conflicting roles
    violations := [user |
        user = input.users[_]
        has_conflicting_roles(user)
    ]
    count(violations) == 0
}

has_conflicting_roles(user) if {
    # Check for known conflicting role combinations
    user_roles := {role.name | role := user.roles[_]}
    some conflict in conflicting_role_combinations
    count(user_roles & conflict.roles) >= 2
}

conflicting_role_combinations := [
    {"roles": {"developer", "production_deployer"}, "reason": "Development and production deployment separation"},
    {"roles": {"financial_preparer", "financial_approver"}, "reason": "Financial preparation and approval separation"},
    {"roles": {"user_provisioner", "user_approver"}, "reason": "User provisioning and approval separation"},
    {"roles": {"security_admin", "auditor"}, "reason": "Security administration and audit separation"},
    {"roles": {"database_admin", "application_developer"}, "reason": "Database administration and development separation"},
    {"roles": {"backup_admin", "restore_approver"}, "reason": "Backup administration and restore approval separation"}
]

financial_process_separation if {
    # Financial processes must have proper separation
    financial_sod_violations := [violation |
        process = input.financial_processes[_]
        not financial_process_properly_separated(process)
        violation = {
            "process": process.name,
            "issue": "inadequate_separation",
            "participants": process.participants
        }
    ]
    count(financial_sod_violations) == 0
}

financial_process_properly_separated(process) if {
    # Financial processes need separate people for different roles
    preparers := {user | user := process.participants[_].user_id; process.participants[_].role == "preparer"}
    approvers := {user | user := process.participants[_].user_id; process.participants[_].role == "approver"}
    reviewers := {user | user := process.participants[_].user_id; process.participants[_].role == "reviewer"}

    # No overlap between preparers and approvers
    count(preparers & approvers) == 0
    # No overlap between preparers and reviewers (for critical processes)
    financial_reviewer_separation_ok(process, preparers, reviewers)
}

financial_reviewer_separation_ok(process, preparers, reviewers) if {
    process.criticality_level != "critical"
}

financial_reviewer_separation_ok(process, preparers, reviewers) if {
    count(preparers & reviewers) == 0
}

it_process_separation if {
    # IT processes must have proper separation
    it_sod_violations := [violation |
        process = input.it_processes[_]
        not it_process_properly_separated(process)
        violation = {
            "process": process.name,
            "issue": "inadequate_separation"
        }
    ]
    count(it_sod_violations) == 0
}

it_process_properly_separated(process) if {
    developers := {user | user := process.participants[_].user_id; process.participants[_].role == "developer"}
    deployers := {user | user := process.participants[_].user_id; process.participants[_].role == "deployer"}
    approvers := {user | user := process.participants[_].user_id; process.participants[_].role == "approver"}

    # Developers cannot deploy to production
    it_deployment_separation_ok(process, developers, deployers)
    # Developers cannot approve their own deployments
    count(developers & approvers) == 0
}

it_deployment_separation_ok(process, developers, deployers) if {
    process.environment != "production"
}

it_deployment_separation_ok(process, developers, deployers) if {
    count(developers & deployers) == 0
}

approval_workflow_separation if {
    # Approval workflows must enforce separation
    workflow_violations := [workflow |
        workflow = input.approval_workflows[_]
        not approval_workflow_properly_configured(workflow)
    ]
    count(workflow_violations) == 0
}

approval_workflow_properly_configured(workflow) if {
    # Requesters cannot approve their own requests
    workflow.self_approval_prohibited == true
    # Multiple approvers required for high-risk requests
    workflow_approval_count_valid(workflow)
    # Escalation procedures in place
    workflow.escalation_procedures_defined == true
}

workflow_approval_count_valid(workflow) if {
    workflow.risk_level != "high"
}

workflow_approval_count_valid(workflow) if {
    count(workflow.required_approvers) >= 2
}

# Account Lifecycle Management
# Corporate Policy: "User accounts must be properly provisioned, maintained, and deprovisioned"
account_lifecycle_managed if {
    account_provisioning_controlled
    account_maintenance_performed
    account_deprovisioning_timely
    orphaned_accounts_managed
}

account_provisioning_controlled if {
    # New accounts must follow proper procedures
    violations := [user |
        user = input.users[_]
        user.status == "active"
        not account_provisioning_adequate(user)
    ]
    count(violations) == 0
}

account_provisioning_adequate(user) if {
    user.provisioning.manager_approval == true
    user.provisioning.hr_verification == true
    user.provisioning.security_clearance_verified == true
    user.provisioning.access_request_documented == true
}

account_maintenance_performed if {
    # Accounts must be regularly reviewed and updated
    overdue_reviews := [user |
        user = input.users[_]
        user.status == "active"
        account_review_overdue(user)
    ]
    count(overdue_reviews) == 0
}

account_review_overdue(user) if {
    days_since_review := (time.now_ns() - user.last_access_review) / (24 * 60 * 60 * 1000000000)
    days_since_review > review_frequency_days(user)
}

review_frequency_days(user) := 30 if {
    user_has_privileged_access(user)
}

review_frequency_days(user) := 90 if {
    not user_has_privileged_access(user)
}

account_deprovisioning_timely if {
    # Terminated users must be deprovisioned promptly
    violations := [user |
        user = input.users[_]
        user.employment_status == "terminated"
        not account_deprovisioning_adequate(user)
    ]
    count(violations) == 0
}

account_deprovisioning_adequate(user) if {
    user.status == "disabled"
    termination_hours := (time.now_ns() - user.termination_date) / (60 * 60 * 1000000000)
    termination_hours <= max_deprovisioning_hours(user)
}

max_deprovisioning_hours(user) := 2 if {
    user_has_privileged_access(user)
}

max_deprovisioning_hours(user) := 4 if {
    not user_has_privileged_access(user)
}

orphaned_accounts_managed if {
    # Accounts without active owners must be identified and managed
    orphaned := [user |
        user = input.users[_]
        user.status == "active"
        account_is_orphaned(user)
    ]
    count(orphaned) == 0
}

account_is_orphaned(user) if {
    not user.manager_id
}

account_is_orphaned(user) if {
    manager := input.users[user.manager_id]
    manager.status != "active"
}

# Access Monitoring and Alerting
# Corporate Policy: "All access must be monitored and suspicious activity detected"
access_monitoring_enabled if {
    login_monitoring_configured
    privilege_escalation_detected
    suspicious_activity_alerting
    access_pattern_analysis
}

login_monitoring_configured if {
    # All login attempts must be logged and monitored
    every system in input.systems {
        system.login_monitoring.enabled == true
        system.login_monitoring.failed_attempts_threshold <= 5
        system.login_monitoring.lockout_duration >= 30  # minutes
    }
}

privilege_escalation_detected if {
    # Privilege escalation attempts must be detected
    every system in input.systems {
        system.privilege_monitoring.enabled == true
        system.privilege_monitoring.sudo_logging == true
        system.privilege_monitoring.admin_activity_monitoring == true
    }
}

suspicious_activity_alerting if {
    # Suspicious access patterns must trigger alerts
    every alert_rule in input.access_monitoring.alert_rules {
        alert_rule.enabled == true
        alert_rule.response_time_minutes <= alert_response_time(alert_rule.severity)
    }
}

alert_response_time("critical") := 5   # 5 minutes
alert_response_time("high") := 15      # 15 minutes
alert_response_time("medium") := 60    # 1 hour
alert_response_time("low") := 240      # 4 hours

access_pattern_analysis if {
    # Access patterns must be analyzed for anomalies
    input.access_monitoring.behavioral_analysis.enabled == true
    input.access_monitoring.geolocation_monitoring.enabled == true
    input.access_monitoring.time_based_analysis.enabled == true
}

# Multi-Factor Authentication (MFA) Requirements
# Corporate Policy: "MFA required for all privileged access and sensitive systems"
mfa_requirements_met if {
    privileged_users_have_mfa
    sensitive_systems_require_mfa
    mfa_backup_methods_configured
    mfa_policy_enforced
}

privileged_users_have_mfa if {
    # All privileged users must have MFA enabled
    violations := [user |
        user = input.users[_]
        user_has_privileged_access(user)
        not user.mfa_enabled == true
    ]
    count(violations) == 0
}

sensitive_systems_require_mfa if {
    # Sensitive systems must enforce MFA
    violations := [system |
        system = input.systems[_]
        system.sensitivity_level in ["confidential", "restricted"]
        not system.mfa_required == true
    ]
    count(violations) == 0
}

mfa_backup_methods_configured if {
    # Users must have backup MFA methods
    violations := [user |
        user = input.users[_]
        user.mfa_enabled == true
        count(user.mfa_methods) < 2
    ]
    count(violations) == 0
}

mfa_policy_enforced if {
    # MFA policy must be technically enforced
    input.mfa_policy.enforcement_mode == "enforced"
    input.mfa_policy.bypass_allowed == false
    input.mfa_policy.session_timeout_minutes <= 480  # 8 hours max
}

# Access Control Violations and Remediation
access_control_violations := violations if {
    violations := array.concat(
        rbac_violations,
        array.concat(privileged_access_violations,
        array.concat(sod_violations,
        array.concat(lifecycle_violations, monitoring_violations)))
    )
}

rbac_violations := [violation |
    user = input.users[_]
    excessive_permissions(user)
    violation = {
        "type": "excessive_permissions",
        "severity": "high",
        "user_id": user.id,
        "description": sprintf("User %s has excessive permissions for job function %s", [user.id, user.job_function]),
        "remediation": "Review and remove unnecessary role assignments"
    }
]

privileged_access_violations := [violation |
    user = input.users[_]
    user_has_privileged_access(user)
    not privileged_controls_adequate(user)
    violation = {
        "type": "inadequate_privileged_controls",
        "severity": "critical",
        "user_id": user.id,
        "description": sprintf("Privileged user %s lacks adequate security controls", [user.id]),
        "remediation": "Implement MFA, session recording, and approval workflows"
    }
]

sod_violations := [violation |
    user = input.users[_]
    has_conflicting_roles(user)
    violation = {
        "type": "segregation_of_duties",
        "severity": "high",
        "user_id": user.id,
        "description": sprintf("User %s has conflicting roles that violate segregation of duties", [user.id]),
        "remediation": "Remove conflicting role assignments and redistribute duties"
    }
]

lifecycle_violations := [violation |
    user = input.users[_]
    user.employment_status == "terminated"
    user.status == "active"
    violation = {
        "type": "account_deprovisioning",
        "severity": "critical",
        "user_id": user.id,
        "description": sprintf("Terminated user %s still has active account", [user.id]),
        "remediation": "Immediately disable account and revoke all access"
    }
]

monitoring_violations := [violation |
    system = input.systems[_]
    not system.login_monitoring.enabled
    violation = {
        "type": "access_monitoring",
        "severity": "medium",
        "system_id": system.id,
        "description": sprintf("System %s lacks proper access monitoring", [system.id]),
        "remediation": "Enable comprehensive access logging and monitoring"
    }
]

# Access Control Score
access_control_score := score if {
    total_checks := 6
    passed_checks := count([check |
        checks = [
            rbac_implemented,
            privileged_access_managed,
            segregation_of_duties_enforced,
            account_lifecycle_managed,
            access_monitoring_enabled,
            mfa_requirements_met
        ]
        check = checks[_]
        check == true
    ])
    score := (passed_checks * 100) / total_checks
}

# Compliance Framework Mapping
sox_access_control_compliant if {
    access_control_compliant
    segregation_of_duties_enforced
    # Additional SOX-specific controls
    every user in input.users {
        "financial_reporting" in user.system_access
        user.quarterly_access_review == true
    }
}

pci_dss_access_control_compliant if {
    access_control_compliant
    # Additional PCI DSS requirements
    every user in input.users {
        "cardholder_data" in user.data_access
        user.mfa_enabled == true
        user.unique_user_id == true
    }
}

# Policy Metadata
access_control_metadata := {
    "policy_name": "Access Control and Identity Management Policy",
    "version": "2.3",
    "effective_date": "2025-01-01",
    "last_updated": "2025-10-05",
    "policy_owner": "Chief Information Security Officer",
    "compliance_frameworks": ["SOX", "PCI DSS", "ISO 27001", "NIST CSF"],
    "enforcement_level": "mandatory",
    "review_frequency": "quarterly",
    "exception_approval_required": true
}