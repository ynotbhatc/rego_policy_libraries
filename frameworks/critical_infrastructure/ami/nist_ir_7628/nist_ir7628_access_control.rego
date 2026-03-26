package ami.nist_ir7628.access_control

import rego.v1

# NIST IR 7628 Rev 1 - Smart Grid Cybersecurity
# Control Family: SG.AC - Access Control
# Scope: AMI head-end systems, communication networks, meter management

# SG.AC-1: Access Control Policy and Procedures
# An access control policy must be documented, approved, and reviewed annually
ac_policy_documented if {
    input.access_control.policy.documented == true
    input.access_control.policy.approved == true
}

ac_policy_current if {
    last_review_ns := time.parse_rfc3339_ns(input.access_control.policy.last_review_date)
    age_days := (time.now_ns() - last_review_ns) / (24 * 60 * 60 * 1000000000)
    age_days <= 365
}

# SG.AC-2: Account Management
# User accounts must be managed with formal processes
account_management_implemented if {
    input.access_control.accounts.formal_provisioning == true
    input.access_control.accounts.formal_deprovisioning == true
    input.access_control.accounts.periodic_review == true
}

# SG.AC-3: Access Enforcement - Default Deny
# Systems must enforce default-deny access control
default_deny_enforced if {
    input.access_control.enforcement.default_deny == true
}

# SG.AC-6: Least Privilege
# Users and processes have only the minimum access needed
least_privilege_enforced if {
    input.access_control.enforcement.least_privilege == true
    input.access_control.enforcement.privilege_separation == true
}

# SG.AC-11: Session Authenticity / Session Management
# Sessions must use secure tokens with timeout enforcement
session_management_secure if {
    input.access_control.sessions.secure_tokens == true
    input.access_control.sessions.timeout_minutes <= 30
    input.access_control.sessions.concurrent_sessions_limited == true
}

# SG.AC-17: Remote Access
# Remote access to AMI systems must use MFA and encrypted channels
remote_access_secure if {
    input.access_control.remote_access.mfa_required == true
    input.access_control.remote_access.encrypted_channel == true
    input.access_control.remote_access.vpn_required == true
}

# SG.AC-1: Violation — missing or outdated access control policy
violations contains msg if {
    not ac_policy_documented
    msg := "SG.AC-1: Access control policy is not documented or approved"
}

violations contains msg if {
    ac_policy_documented
    not ac_policy_current
    msg := "SG.AC-1: Access control policy has not been reviewed within the past 365 days"
}

# SG.AC-2: Violation — missing account management
violations contains msg if {
    not account_management_implemented
    msg := "SG.AC-2: Formal account provisioning/deprovisioning process not implemented"
}

# SG.AC-3: Violation — no default deny
violations contains msg if {
    not default_deny_enforced
    msg := "SG.AC-3: Default-deny access enforcement not configured"
}

# SG.AC-6: Violation — least privilege not enforced
violations contains msg if {
    not least_privilege_enforced
    msg := "SG.AC-6: Least privilege and privilege separation not enforced"
}

# SG.AC-11: Violation — weak session management
violations contains msg if {
    not session_management_secure
    msg := "SG.AC-11: Session management does not enforce secure tokens or 30-minute timeout"
}

# SG.AC-17: Violation — insecure remote access
violations contains msg if {
    not remote_access_secure
    msg := "SG.AC-17: Remote access does not require MFA, VPN, and encrypted channel"
}

# Overall compliance
default compliant := false

compliant if {
    count(violations) == 0
}

compliance_report := {
    "control_family": "SG.AC",
    "framework": "NIST IR 7628 Rev 1",
    "controls_assessed": ["SG.AC-1", "SG.AC-2", "SG.AC-3", "SG.AC-6", "SG.AC-11", "SG.AC-17"],
    "total_violations": count(violations),
    "compliant": compliant,
    "violations": violations,
}
