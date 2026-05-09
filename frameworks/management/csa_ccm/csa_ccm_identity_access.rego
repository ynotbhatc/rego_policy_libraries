package csa_ccm.identity_access

import rego.v1

default compliant := false

violations contains msg if {
    not input.csa_ccm.identity_access.iam_policy.policy_established
    msg := "IAM-01: Identity and access management policy not formally established"
}

violations contains msg if {
    not input.csa_ccm.identity_access.iam_policy.cloud_identities_in_scope
    msg := "IAM-01: Cloud identity management not included in IAM policy scope"
}

violations contains msg if {
    not input.csa_ccm.identity_access.iam_policy.policy_reviewed_annually
    msg := "IAM-01: IAM policy not reviewed and updated at least annually"
}

violations contains msg if {
    not input.csa_ccm.identity_access.iam_policy.least_privilege_principle_adopted
    msg := "IAM-01: Least-privilege access principle not formally adopted in IAM policy"
}

violations contains msg if {
    not input.csa_ccm.identity_access.identity_lifecycle.provisioning_process_defined
    msg := "IAM-02: Identity provisioning process not defined — formal procedure for creating and managing accounts required"
}

violations contains msg if {
    not input.csa_ccm.identity_access.identity_lifecycle.deprovisioning_process_defined
    msg := "IAM-02: Identity deprovisioning process not defined — accounts must be removed or disabled promptly when no longer needed"
}

violations contains msg if {
    not input.csa_ccm.identity_access.identity_lifecycle.unique_identities_enforced
    msg := "IAM-02: Unique identities not enforced — shared accounts must be prohibited except where technically required"
}

violations contains msg if {
    not input.csa_ccm.identity_access.identity_lifecycle.identity_verified_before_provisioning
    msg := "IAM-02: Identity verification not performed before provisioning accounts with access to sensitive systems"
}

violations contains msg if {
    not input.csa_ccm.identity_access.mfa.mfa_enforced
    msg := "IAM-03: Multi-factor authentication (MFA) not enforced for access to cloud management consoles and sensitive systems"
}

violations contains msg if {
    not input.csa_ccm.identity_access.mfa.mfa_on_privileged_accounts
    msg := "IAM-03: MFA not enforced for all privileged accounts — administrative access requires MFA without exception"
}

violations contains msg if {
    not input.csa_ccm.identity_access.mfa.mfa_on_remote_access
    msg := "IAM-03: MFA not enforced for remote access connections (VPN, remote desktop, SSH with key-only insufficient)"
}

violations contains msg if {
    not input.csa_ccm.identity_access.mfa.phishing_resistant_mfa_for_admins
    msg := "IAM-03: Phishing-resistant MFA not used for administrative accounts — FIDO2/hardware keys required for high-privilege access"
}

violations contains msg if {
    not input.csa_ccm.identity_access.privileged_access.pam_solution_deployed
    msg := "IAM-04: Privileged access management (PAM) solution not deployed to control and audit privileged account usage"
}

violations contains msg if {
    not input.csa_ccm.identity_access.privileged_access.privileged_accounts_inventoried
    msg := "IAM-04: Privileged accounts not inventoried — all accounts with elevated access must be catalogued"
}

violations contains msg if {
    not input.csa_ccm.identity_access.privileged_access.privileged_sessions_recorded
    msg := "IAM-04: Privileged sessions not recorded — administrative sessions must be captured for audit and forensic purposes"
}

violations contains msg if {
    not input.csa_ccm.identity_access.privileged_access.standing_privilege_minimized
    msg := "IAM-04: Standing privileged access not minimized — just-in-time access must be implemented where feasible"
}

violations contains msg if {
    not input.csa_ccm.identity_access.privileged_access.break_glass_procedure_defined
    msg := "IAM-04: Break-glass emergency access procedure not defined for privileged accounts"
}

violations contains msg if {
    not input.csa_ccm.identity_access.sso.sso_implemented
    msg := "IAM-05: Single sign-on (SSO) not implemented for cloud applications to centralize access management"
}

violations contains msg if {
    input.csa_ccm.identity_access.sso.sso_implemented
    not input.csa_ccm.identity_access.sso.sso_uses_federated_identity
    msg := "IAM-05: SSO not federated with enterprise identity provider — applications must authenticate through central IdP"
}

violations contains msg if {
    not input.csa_ccm.identity_access.sso.sso_session_timeout_configured
    msg := "IAM-05: SSO session timeout not configured — idle sessions must expire after defined period of inactivity"
}

violations contains msg if {
    not input.csa_ccm.identity_access.service_accounts.service_accounts_inventoried
    msg := "IAM-06: Service accounts not inventoried — all non-human identities must be catalogued with their purpose and owner"
}

violations contains msg if {
    not input.csa_ccm.identity_access.service_accounts.service_account_credentials_rotated
    msg := "IAM-06: Service account credentials not rotated on defined schedule — static credentials create persistent risk"
}

violations contains msg if {
    not input.csa_ccm.identity_access.service_accounts.service_account_permissions_minimal
    msg := "IAM-06: Service account permissions not minimized — accounts must have only the access required for their function"
}

violations contains msg if {
    not input.csa_ccm.identity_access.service_accounts.managed_identities_preferred
    msg := "IAM-06: Managed identities or workload identity federation not preferred over static service account credentials"
}

violations contains msg if {
    not input.csa_ccm.identity_access.access_reviews.reviews_conducted
    msg := "IAM-07: Access reviews not conducted at defined intervals to verify access remains appropriate"
}

violations contains msg if {
    not input.csa_ccm.identity_access.access_reviews.privileged_access_reviewed_frequently
    msg := "IAM-07: Privileged access not reviewed more frequently than standard user access"
}

violations contains msg if {
    not input.csa_ccm.identity_access.access_reviews.inappropriate_access_revoked
    msg := "IAM-07: Inappropriate access identified during reviews not revoked within defined timeframe"
}

violations contains msg if {
    not input.csa_ccm.identity_access.access_reviews.review_results_documented
    msg := "IAM-07: Access review results not documented and retained for audit purposes"
}

violations contains msg if {
    not input.csa_ccm.identity_access.jit_access.jit_implemented_for_privileged
    msg := "IAM-08: Just-in-time (JIT) access not implemented for privileged cloud management access"
}

violations contains msg if {
    not input.csa_ccm.identity_access.jit_access.access_requests_approved
    msg := "IAM-08: JIT access requests not subject to approval before access is granted"
}

violations contains msg if {
    not input.csa_ccm.identity_access.jit_access.jit_access_time_limited
    msg := "IAM-08: JIT access not time-limited — elevated access must automatically expire after defined duration"
}

violations contains msg if {
    not input.csa_ccm.identity_access.rbac.rbac_implemented
    msg := "IAM-09: Role-based access control (RBAC) not implemented — access must be granted based on defined roles"
}

violations contains msg if {
    not input.csa_ccm.identity_access.rbac.roles_defined_per_job_function
    msg := "IAM-09: RBAC roles not defined per job function — access groups must align to business role requirements"
}

violations contains msg if {
    not input.csa_ccm.identity_access.rbac.excessive_role_assignments_detected
    msg := "IAM-09: Excessive role assignments not detected and remediated — personnel must not accumulate unnecessary roles"
}

violations contains msg if {
    not input.csa_ccm.identity_access.zero_trust.network_implicit_trust_eliminated
    msg := "IAM-10: Implicit network trust not eliminated — zero trust principles require verification of every access request"
}

violations contains msg if {
    not input.csa_ccm.identity_access.zero_trust.continuous_verification_implemented
    msg := "IAM-10: Continuous identity and device verification not implemented — trust must be continuously validated"
}

violations contains msg if {
    not input.csa_ccm.identity_access.zero_trust.microsegmentation_applied
    msg := "IAM-10: Microsegmentation not applied to limit lateral movement within cloud environments"
}

violations contains msg if {
    not input.csa_ccm.identity_access.password_policy.password_policy_enforced
    msg := "IAM-11: Password policy not enforced for user accounts — minimum complexity and length requirements must be configured"
}

violations contains msg if {
    not input.csa_ccm.identity_access.password_policy.minimum_length_enforced
    msg := "IAM-11: Password minimum length not enforced — passwords must meet minimum length requirements (14+ characters)"
}

violations contains msg if {
    not input.csa_ccm.identity_access.password_policy.breached_password_detection
    msg := "IAM-11: Breached password detection not implemented — compromised passwords must be blocked or flagged"
}

violations contains msg if {
    not input.csa_ccm.identity_access.account_lockout.lockout_policy_configured
    msg := "IAM-12: Account lockout policy not configured — repeated failed authentication attempts must lock accounts"
}

violations contains msg if {
    not input.csa_ccm.identity_access.account_lockout.lockout_threshold_appropriate
    msg := "IAM-12: Account lockout threshold too high — maximum failed attempts before lockout must be set to 10 or fewer"
}

violations contains msg if {
    not input.csa_ccm.identity_access.federated_identity.federation_implemented
    msg := "IAM-13: Federated identity not implemented — cloud access must authenticate through enterprise directory"
}

violations contains msg if {
    not input.csa_ccm.identity_access.federated_identity.directory_sync_operational
    msg := "IAM-13: Directory synchronization not operational — cloud identity must reflect current enterprise directory state"
}

violations contains msg if {
    not input.csa_ccm.identity_access.federated_identity.terminated_users_deprovisioned_automatically
    msg := "IAM-13: Terminated users not automatically deprovisioned from cloud systems via directory synchronization"
}

violations contains msg if {
    not input.csa_ccm.identity_access.privileged_identity.privileged_identity_governance_defined
    msg := "IAM-14: Privileged identity governance not defined — lifecycle of privileged accounts must be formally managed"
}

violations contains msg if {
    not input.csa_ccm.identity_access.privileged_identity.admin_accounts_separate_from_user_accounts
    msg := "IAM-14: Administrative accounts not separate from standard user accounts — separate identities required for privileged tasks"
}

violations contains msg if {
    not input.csa_ccm.identity_access.privileged_identity.global_admin_accounts_minimized
    msg := "IAM-14: Number of global administrator accounts not minimized — highest-privilege roles must have the fewest holders"
}

compliant if { count(violations) == 0 }

compliance_report := {
    "domain": "IAM — Identity & Access Management",
    "compliant": compliant,
    "violation_count": count(violations),
    "violations": violations,
}
