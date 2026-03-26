package hipaa.access_control

import rego.v1

# =============================================================================
# HIPAA Security Rule — 45 CFR 164.312(a)
# Technical Safeguard: Access Control
#
# Required Specifications:
#   164.312(a)(2)(i)  - Unique User Identification (R)
#   164.312(a)(2)(ii) - Emergency Access Procedure (R)
#   164.312(a)(2)(iii)- Automatic Logoff (A)
#   164.312(a)(2)(iv) - Encryption and Decryption (A)
#
# Input shape:
#   input.users[]               - user accounts on the system
#   input.access_controls       - access control configuration
#   input.session               - session management settings
#   input.encryption            - encryption/decryption capabilities
#   input.phi_systems[]         - systems storing ePHI
# =============================================================================

# ---------------------------------------------------------------------------
# 164.312(a)(2)(i) — Unique User Identification (Required)
# Assign a unique name/number for identifying and tracking user identity
# ---------------------------------------------------------------------------

violation_unique_user_id contains msg if {
    some user in input.users
    user.shared_account == true
    msg := sprintf(
        "HIPAA 164.312(a)(2)(i): User account '%v' is a shared account. Each user must have a unique identifier.",
        [user.username]
    )
}

violation_unique_user_id contains msg if {
    some user in input.users
    not user.username
    msg := "HIPAA 164.312(a)(2)(i): User account found with no username — unique identification required."
}

violation_unique_user_id contains msg if {
    generic_accounts := [u | some u in input.users; u.username in {"admin", "administrator", "root", "guest", "test", "demo", "shared"}; not u.phi_access_disabled]
    count(generic_accounts) > 0
    msg := sprintf(
        "HIPAA 164.312(a)(2)(i): Generic/shared accounts with potential ePHI access detected: %v. Disable or restrict these accounts.",
        [[u.username | some u in generic_accounts]]
    )
}

control_a2i_compliant if {
    count(violation_unique_user_id) == 0
}

# ---------------------------------------------------------------------------
# 164.312(a)(2)(ii) — Emergency Access Procedure (Required)
# Obtain necessary ePHI during an emergency
# ---------------------------------------------------------------------------

violation_emergency_access contains msg if {
    not input.access_controls.emergency_access_procedure_documented
    msg := "HIPAA 164.312(a)(2)(ii): No documented emergency access procedure found. An emergency access procedure for ePHI must be documented and implemented."
}

violation_emergency_access contains msg if {
    not input.access_controls.emergency_access_tested
    msg := "HIPAA 164.312(a)(2)(ii): Emergency access procedure has not been tested. Procedures must be regularly tested to ensure operability."
}

violation_emergency_access contains msg if {
    input.access_controls.emergency_accounts_reviewed_days > 90
    msg := sprintf(
        "HIPAA 164.312(a)(2)(ii): Emergency access accounts have not been reviewed in %v days (maximum: 90 days).",
        [input.access_controls.emergency_accounts_reviewed_days]
    )
}

control_a2ii_compliant if {
    count(violation_emergency_access) == 0
}

# ---------------------------------------------------------------------------
# 164.312(a)(2)(iii) — Automatic Logoff (Addressable)
# Terminate electronic session after predetermined time of inactivity
# ---------------------------------------------------------------------------

violation_automatic_logoff contains msg if {
    not input.session.automatic_logoff_enabled
    msg := "HIPAA 164.312(a)(2)(iii): Automatic logoff is not enabled. Sessions must terminate after inactivity."
}

violation_automatic_logoff contains msg if {
    input.session.automatic_logoff_enabled
    input.session.inactivity_timeout_minutes > 15
    msg := sprintf(
        "HIPAA 164.312(a)(2)(iii): Automatic logoff timeout is %v minutes. Recommended maximum is 15 minutes for systems with ePHI access.",
        [input.session.inactivity_timeout_minutes]
    )
}

violation_automatic_logoff contains msg if {
    input.session.screen_lock_enabled == false
    msg := "HIPAA 164.312(a)(2)(iii): Screen lock is not enabled. Unattended workstations accessing ePHI must lock automatically."
}

control_a2iii_compliant if {
    count(violation_automatic_logoff) == 0
}

# ---------------------------------------------------------------------------
# 164.312(a)(2)(iv) — Encryption and Decryption (Addressable)
# Implement a mechanism to encrypt and decrypt ePHI
# ---------------------------------------------------------------------------

violation_encryption contains msg if {
    some phi_system in input.phi_systems
    not phi_system.data_at_rest_encrypted
    msg := sprintf(
        "HIPAA 164.312(a)(2)(iv): System '%v' stores ePHI but data-at-rest encryption is not enabled.",
        [phi_system.name]
    )
}

violation_encryption contains msg if {
    some phi_system in input.phi_systems
    phi_system.data_at_rest_encrypted
    phi_system.encryption_algorithm in {"DES", "3DES", "RC4", "RC2", "MD5"}
    msg := sprintf(
        "HIPAA 164.312(a)(2)(iv): System '%v' uses deprecated encryption algorithm '%v'. Use AES-256 or equivalent.",
        [phi_system.name, phi_system.encryption_algorithm]
    )
}

violation_encryption contains msg if {
    not input.encryption.key_management_policy_documented
    msg := "HIPAA 164.312(a)(2)(iv): No documented encryption key management policy. Key management procedures must be documented."
}

violation_encryption contains msg if {
    input.encryption.key_rotation_days > 365
    msg := sprintf(
        "HIPAA 164.312(a)(2)(iv): Encryption keys have not been rotated in %v days. Annual rotation is recommended.",
        [input.encryption.key_rotation_days]
    )
}

control_a2iv_compliant if {
    count(violation_encryption) == 0
}

# ---------------------------------------------------------------------------
# Role-Based Access Control (RBAC) for ePHI
# ---------------------------------------------------------------------------

violation_rbac contains msg if {
    not input.access_controls.role_based_access_implemented
    msg := "HIPAA 164.312(a)(1): Role-based access control not implemented. Access to ePHI must be based on job function."
}

violation_rbac contains msg if {
    some user in input.users
    user.phi_access == true
    not user.phi_access_justified
    msg := sprintf(
        "HIPAA 164.312(a)(1): User '%v' has ePHI access with no documented business justification.",
        [user.username]
    )
}

violation_rbac contains msg if {
    some user in input.users
    user.phi_access == true
    user.last_access_review_days > 90
    msg := sprintf(
        "HIPAA 164.312(a)(1): User '%v' ePHI access has not been reviewed in %v days (maximum: 90 days).",
        [user.username, user.last_access_review_days]
    )
}

# ---------------------------------------------------------------------------
# Minimum Necessary Access
# ---------------------------------------------------------------------------

violation_minimum_necessary contains msg if {
    some user in input.users
    user.phi_access_level == "full"
    not user.minimum_necessary_justified
    msg := sprintf(
        "HIPAA 164.514(d): User '%v' has full ePHI access. Minimum necessary access principle requires limiting access to only what is needed.",
        [user.username]
    )
}

# ---------------------------------------------------------------------------
# All violations aggregated
# ---------------------------------------------------------------------------

violations contains msg if {
    some msg in violation_unique_user_id
}

violations contains msg if {
    some msg in violation_emergency_access
}

violations contains msg if {
    some msg in violation_automatic_logoff
}

violations contains msg if {
    some msg in violation_encryption
}

violations contains msg if {
    some msg in violation_rbac
}

violations contains msg if {
    some msg in violation_minimum_necessary
}

# ---------------------------------------------------------------------------
# Overall compliance
# ---------------------------------------------------------------------------

compliant if {
    count(violations) == 0
}

compliance_report := {
    "section":        "164.312(a)",
    "title":          "Access Control",
    "required":       true,
    "compliant":      compliant,
    "violation_count": count(violations),
    "violations":     violations,
    "controls": {
        "unique_user_id":       control_a2i_compliant,
        "emergency_access":     control_a2ii_compliant,
        "automatic_logoff":     control_a2iii_compliant,
        "encryption_decryption": control_a2iv_compliant,
    },
}
