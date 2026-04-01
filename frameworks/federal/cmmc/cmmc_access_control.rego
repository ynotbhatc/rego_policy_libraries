package cmmc.access_control

import rego.v1

# =============================================================================
# CMMC 2.0 — Access Control Domain (AC)
# Cybersecurity Maturity Model Certification
# Based on NIST SP 800-171 Rev 2 with CMMC maturity levels
#
# Levels:
#   Level 1 (Foundational) — 17 practices, FAR clause 52.204-21
#   Level 2 (Advanced)     — 110 practices, NIST 800-171
#   Level 3 (Expert)       — 110+ practices, NIST 800-172
#
# Input shape:
#   input.users[]               - user accounts
#   input.access_controls       - access control configuration
#   input.session               - session management
#   input.cui_systems[]         - systems storing Controlled Unclassified Information
#   input.cmmc_level            - target maturity level (1, 2, or 3)
# =============================================================================

# ---------------------------------------------------------------------------
# Level 1 (Foundational) — AC practices
# ---------------------------------------------------------------------------

# AC.L1-3.1.1 — Limit information system access to authorized users
violation_l1_ac_1_1 contains msg if {
    some user in input.users
    user.authorized == false
    user.system_access == true
    msg := sprintf(
        "CMMC AC.L1-3.1.1: Unauthorized user '%v' has system access. Access must be limited to authorized users only.",
        [user.username]
    )
}

# AC.L1-3.1.2 — Limit information system access to types of transactions
violation_l1_ac_1_2 contains msg if {
    not input.access_controls.least_privilege_enforced
    msg := "CMMC AC.L1-3.1.2: Least privilege access is not enforced. Users must be limited to transactions necessary for their role."
}

# AC.L1-3.1.20 — Verify/control connections to external information systems
violation_l1_ac_1_20 contains msg if {
    not input.access_controls.external_connections_controlled
    msg := "CMMC AC.L1-3.1.20: External system connections are not controlled. All connections to external systems must be verified and controlled."
}

# AC.L1-3.1.22 — Control information posted or processed on publicly accessible systems
violation_l1_ac_1_22 contains msg if {
    some system in input.cui_systems
    system.publicly_accessible == true
    not system.cui_posting_controls
    msg := sprintf(
        "CMMC AC.L1-3.1.22: CUI system '%v' is publicly accessible without CUI posting controls.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# Level 2 (Advanced) — Additional AC practices from NIST 800-171
# ---------------------------------------------------------------------------

# AC.L2-3.1.3 — Control the flow of CUI
violation_l2_ac_1_3 contains msg if {
    input.cmmc_level >= 2
    not input.access_controls.cui_flow_controls
    msg := "CMMC AC.L2-3.1.3: No CUI information flow controls implemented. Data flow enforcement is required at Level 2."
}

# AC.L2-3.1.4 — Separate duties of individuals to reduce risk of malevolent activity
violation_l2_ac_1_4 contains msg if {
    input.cmmc_level >= 2
    not input.access_controls.separation_of_duties
    msg := "CMMC AC.L2-3.1.4: Separation of duties is not implemented. No single user should be able to complete a high-risk action alone."
}

# AC.L2-3.1.5 — Employ least privilege
violation_l2_ac_1_5 contains msg if {
    input.cmmc_level >= 2
    some user in input.users
    user.privileged == true
    not user.privilege_justified
    msg := sprintf(
        "CMMC AC.L2-3.1.5: Privileged user '%v' has no documented justification. Least privilege must be enforced with documented need.",
        [user.username]
    )
}

# AC.L2-3.1.6 — Use non-privileged accounts for non-privileged actions
violation_l2_ac_1_6 contains msg if {
    input.cmmc_level >= 2
    some user in input.users
    user.privileged == true
    not user.non_privileged_account_for_regular_use
    msg := sprintf(
        "CMMC AC.L2-3.1.6: Privileged user '%v' does not have a separate non-privileged account for routine tasks.",
        [user.username]
    )
}

# AC.L2-3.1.7 — Prevent non-privileged users from executing privileged functions
violation_l2_ac_1_7 contains msg if {
    input.cmmc_level >= 2
    not input.access_controls.privileged_function_auditing
    msg := "CMMC AC.L2-3.1.7: Privileged function execution is not audited. All privileged function use must be logged."
}

# AC.L2-3.1.10 — Use session lock
violation_l2_ac_1_10 contains msg if {
    input.cmmc_level >= 2
    input.session.lock_timeout_minutes > 15
    msg := sprintf(
        "CMMC AC.L2-3.1.10: Session lock timeout is %v minutes. Maximum 15 minutes of inactivity before lock is required.",
        [input.session.lock_timeout_minutes]
    )
}

# AC.L2-3.1.11 — Terminate sessions after defined period
violation_l2_ac_1_11 contains msg if {
    input.cmmc_level >= 2
    not input.session.automatic_termination
    msg := "CMMC AC.L2-3.1.11: Sessions are not automatically terminated after inactivity. Implement session termination for CUI access."
}

# AC.L2-3.1.12 — Monitor and control remote access sessions
violation_l2_ac_1_12 contains msg if {
    input.cmmc_level >= 2
    not input.access_controls.remote_access_monitored
    msg := "CMMC AC.L2-3.1.12: Remote access sessions are not monitored. All remote access to CUI systems must be monitored."
}

# AC.L2-3.1.13 — Use cryptographic mechanisms for remote access
violation_l2_ac_1_13 contains msg if {
    input.cmmc_level >= 2
    not input.access_controls.remote_access_encrypted
    msg := "CMMC AC.L2-3.1.13: Remote access does not use cryptographic mechanisms. VPN or equivalent encryption is required."
}

# AC.L2-3.1.14 — Route remote access via managed access control points
violation_l2_ac_1_14 contains msg if {
    input.cmmc_level >= 2
    not input.access_controls.remote_access_via_managed_points
    msg := "CMMC AC.L2-3.1.14: Remote access is not routed through managed access control points (e.g., jump servers, VPN gateways)."
}

# AC.L2-3.1.15 — Authorize remote execution of privileged commands
violation_l2_ac_1_15 contains msg if {
    input.cmmc_level >= 2
    not input.access_controls.remote_privileged_commands_controlled
    msg := "CMMC AC.L2-3.1.15: Remote execution of privileged commands is not controlled. Explicit authorization is required."
}

# AC.L2-3.1.17 — Protect wireless access using authentication/encryption
violation_l2_ac_1_17 contains msg if {
    input.cmmc_level >= 2
    input.access_controls.wireless_access_enabled
    not input.access_controls.wireless_access_encrypted
    msg := "CMMC AC.L2-3.1.17: Wireless access to CUI systems is not encrypted. WPA3 or equivalent is required."
}

# AC.L2-3.1.18 — Control connection of mobile devices
violation_l2_ac_1_18 contains msg if {
    input.cmmc_level >= 2
    not input.access_controls.mobile_device_policy
    msg := "CMMC AC.L2-3.1.18: No mobile device policy for CUI access. Mobile devices connecting to CUI systems must be managed."
}

# AC.L2-3.1.19 — Encrypt CUI on mobile devices
violation_l2_ac_1_19 contains msg if {
    input.cmmc_level >= 2
    input.access_controls.mobile_device_cui_access
    not input.access_controls.mobile_device_encryption
    msg := "CMMC AC.L2-3.1.19: Mobile devices accessing CUI do not enforce encryption. Full-device encryption is required."
}

# ---------------------------------------------------------------------------
# Aggregate violations by level
# ---------------------------------------------------------------------------

level_1_violations contains msg if { some msg in violation_l1_ac_1_1 }
level_1_violations contains msg if { some msg in violation_l1_ac_1_2 }
level_1_violations contains msg if { some msg in violation_l1_ac_1_20 }
level_1_violations contains msg if { some msg in violation_l1_ac_1_22 }

level_2_violations contains msg if { some msg in violation_l2_ac_1_3 }
level_2_violations contains msg if { some msg in violation_l2_ac_1_4 }
level_2_violations contains msg if { some msg in violation_l2_ac_1_5 }
level_2_violations contains msg if { some msg in violation_l2_ac_1_6 }
level_2_violations contains msg if { some msg in violation_l2_ac_1_7 }
level_2_violations contains msg if { some msg in violation_l2_ac_1_10 }
level_2_violations contains msg if { some msg in violation_l2_ac_1_11 }
level_2_violations contains msg if { some msg in violation_l2_ac_1_12 }
level_2_violations contains msg if { some msg in violation_l2_ac_1_13 }
level_2_violations contains msg if { some msg in violation_l2_ac_1_14 }
level_2_violations contains msg if { some msg in violation_l2_ac_1_15 }
level_2_violations contains msg if { some msg in violation_l2_ac_1_17 }
level_2_violations contains msg if { some msg in violation_l2_ac_1_18 }
level_2_violations contains msg if { some msg in violation_l2_ac_1_19 }

violations contains msg if { some msg in level_1_violations }
violations contains msg if {
    input.cmmc_level >= 2
    some msg in level_2_violations
}

compliant if { count(violations) == 0 }

compliance_report := {
    "domain":          "Access Control (AC)",
    "cmmc_level":      input.cmmc_level,
    "compliant":       compliant,
    "violation_count": count(violations),
    "violations":      violations,
    "level_1_passing": count(level_1_violations) == 0,
    "level_2_passing": count(level_2_violations) == 0,
    "passing":         22 - count(violations),
}
