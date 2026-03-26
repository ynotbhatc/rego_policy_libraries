# SOC 2 Trust Service Criteria - Security (CC6.0)
# Access Controls and User Authentication

package soc2.security.access_controls

import rego.v1

# =================================================================
# CC6.1 - Access Controls - Access Rights are Restricted
# =================================================================

# User access is properly restricted based on job responsibilities
user_access_properly_restricted if {
    input.access_controls.role_based_access == true
    input.access_controls.least_privilege_principle == true
    input.access_controls.regular_access_reviews == true
}

# Multi-factor authentication is implemented for privileged access
mfa_for_privileged_access if {
    count(input.access_controls.privileged_users) > 0
    mfa_enabled_users := [user | user := input.access_controls.privileged_users[_]; user.mfa_enabled == true]
    count(mfa_enabled_users) == count(input.access_controls.privileged_users)
}

# System access is monitored and logged
system_access_monitored if {
    input.access_controls.access_logging.enabled == true
    input.access_controls.access_logging.includes_failed_attempts == true
    input.access_controls.access_logging.retention_days >= 90
}

# =================================================================
# CC6.2 - Access Controls - Physical and Logical Access
# =================================================================

# Network access is properly segmented
network_segmentation_implemented if {
    input.network_security.segmentation.enabled == true
    count(input.network_security.segmentation.zones) >= 2
    input.network_security.firewalls.configured == true
}

# Remote access is secured
remote_access_secured if {
    input.remote_access.vpn_required == true
    input.remote_access.vpn_encryption.enabled == true
    input.remote_access.session_timeout.configured == true
    input.remote_access.session_timeout.max_idle_minutes <= 30
}

# Database access is controlled
database_access_controlled if {
    input.database_security.authentication_required == true
    input.database_security.connection_encryption == true
    input.database_security.access_logging == true
    count(input.database_security.privileged_accounts) > 0
    count([account | account := input.database_security.privileged_accounts[_]; account.regular_review == true]) == count(input.database_security.privileged_accounts)
}

# =================================================================
# CC6.3 - Access Controls - Access Rights are Managed
# =================================================================

# User provisioning and deprovisioning is automated
user_lifecycle_managed if {
    input.user_management.automated_provisioning == true
    input.user_management.automated_deprovisioning == true
    input.user_management.approval_workflow == true
}

# Access rights are reviewed regularly
access_rights_reviewed if {
    input.access_controls.periodic_reviews.enabled == true
    input.access_controls.periodic_reviews.frequency_days <= 90
    input.access_controls.periodic_reviews.documented == true
}

# Shared and service accounts are managed
shared_accounts_managed if {
    count(input.access_controls.shared_accounts) == 0
    count([account | 
        account := input.access_controls.service_accounts[_];
        account.unique_identifier == true;
        account.regular_password_change == true
    ]) == count(input.access_controls.service_accounts)
}

# =================================================================
# OpenShift/Kubernetes Specific Controls
# =================================================================

# RBAC is properly configured in OpenShift
openshift_rbac_configured if {
    input.openshift.rbac.enabled == true
    input.openshift.rbac.cluster_admin_users_limited == true
    count(input.openshift.rbac.cluster_admin_users) <= 3
    input.openshift.rbac.service_accounts_restricted == true
}

# Pod security standards are enforced
pod_security_enforced if {
    input.openshift.security.pod_security_standards.enabled == true
    input.openshift.security.pod_security_standards.level in ["restricted", "baseline"]
    input.openshift.security.security_context_constraints.default_restricted == true
}

# Network policies are implemented
network_policies_implemented if {
    input.openshift.network_policies.enabled == true
    input.openshift.network_policies.default_deny == true
    count(input.openshift.network_policies.policies) > 0
}

# Container image security is enforced
container_security_enforced if {
    input.openshift.image_security.scanning_enabled == true
    input.openshift.image_security.vulnerability_threshold.critical == 0
    input.openshift.image_security.vulnerability_threshold.high <= 5
    input.openshift.image_security.trusted_registries_only == true
}

# =================================================================
# Overall Security Assessment
# =================================================================

security_controls_compliant if {
    user_access_properly_restricted
    mfa_for_privileged_access
    system_access_monitored
    network_segmentation_implemented
    remote_access_secured
    database_access_controlled
    user_lifecycle_managed
    access_rights_reviewed
    shared_accounts_managed
}

openshift_security_compliant if {
    openshift_rbac_configured
    pod_security_enforced
    network_policies_implemented
    container_security_enforced
}

overall_security_compliant if {
    security_controls_compliant
    openshift_security_compliant
}

# =================================================================
# Security Score Calculation
# =================================================================

security_score := score if {
    controls := [
        user_access_properly_restricted,
        mfa_for_privileged_access,
        system_access_monitored,
        network_segmentation_implemented,
        remote_access_secured,
        database_access_controlled,
        user_lifecycle_managed,
        access_rights_reviewed,
        shared_accounts_managed,
        openshift_rbac_configured,
        pod_security_enforced,
        network_policies_implemented,
        container_security_enforced
    ]
    
    passed := count([control | control := controls[_]; control == true])
    total := count(controls)
    score := (passed / total) * 100
}

# =================================================================
# Detailed Findings
# =================================================================

security_findings := findings if {
    findings := {
        "user_access_properly_restricted": user_access_properly_restricted,
        "mfa_for_privileged_access": mfa_for_privileged_access,
        "system_access_monitored": system_access_monitored,
        "network_segmentation_implemented": network_segmentation_implemented,
        "remote_access_secured": remote_access_secured,
        "database_access_controlled": database_access_controlled,
        "user_lifecycle_managed": user_lifecycle_managed,
        "access_rights_reviewed": access_rights_reviewed,
        "shared_accounts_managed": shared_accounts_managed,
        "openshift_rbac_configured": openshift_rbac_configured,
        "pod_security_enforced": pod_security_enforced,
        "network_policies_implemented": network_policies_implemented,
        "container_security_enforced": container_security_enforced,
        "overall_score": security_score
    }
}