package cmmc.system_communications_protection

import rego.v1

# =============================================================================
# CMMC 2.0 — Domain 3.13: System and Communications Protection
# NIST SP 800-171 Rev 2 — 16 Practices
# =============================================================================

# 3.13.1 — Monitor, control, and protect communications at the external
#           boundaries and key internal boundaries of organizational systems. (L1)
default compliant_3_13_1 := false
compliant_3_13_1 if {
    input.scp.external_boundary_monitoring == true
    input.scp.internal_boundary_controls == true
    input.scp.network_traffic_controlled == true
}

violation_3_13_1 contains msg if {
    not input.scp.external_boundary_monitoring
    msg := "3.13.1: External network boundaries of CUI systems are not monitored and controlled"
}
violation_3_13_1 contains msg if {
    not input.scp.internal_boundary_controls
    msg := "3.13.1: Key internal network boundaries are not protected (e.g., no segmentation)"
}
violation_3_13_1 contains msg if {
    not input.scp.network_traffic_controlled
    msg := "3.13.1: Network communications are not controlled at organizational boundaries"
}

# 3.13.2 — Employ architectural designs, software development techniques, and
#           systems engineering principles that promote effective information
#           security within organizational systems. (L2)
default compliant_3_13_2 := false
compliant_3_13_2 if {
    input.scp.secure_architecture_principles == true
    input.scp.defense_in_depth_implemented == true
    input.scp.least_functionality_enforced == true
}

violation_3_13_2 contains msg if {
    not input.scp.secure_architecture_principles
    msg := "3.13.2: Secure architecture design principles are not applied to CUI systems"
}
violation_3_13_2 contains msg if {
    not input.scp.defense_in_depth_implemented
    msg := "3.13.2: Defense-in-depth strategy is not implemented for CUI protection"
}
violation_3_13_2 contains msg if {
    not input.scp.least_functionality_enforced
    msg := "3.13.2: Systems are not configured for least functionality (unnecessary features enabled)"
}

# 3.13.3 — Separate user functionality from system management functionality. (L2)
default compliant_3_13_3 := false
compliant_3_13_3 if {
    input.scp.admin_interface_separated == true
    input.scp.user_mgmt_plane_separated == true
}

violation_3_13_3 contains msg if {
    not input.scp.admin_interface_separated
    msg := "3.13.3: System management interfaces are not separated from user interfaces"
}
violation_3_13_3 contains msg if {
    not input.scp.user_mgmt_plane_separated
    msg := "3.13.3: User functionality and system management functionality share the same logical plane"
}

# 3.13.4 — Prevent unauthorized and unintended information transfer via shared
#           system resources. (L2)
default compliant_3_13_4 := false
compliant_3_13_4 if {
    input.scp.shared_resource_controls == true
    input.scp.memory_protection_enabled == true
    input.scp.covert_channel_controls == true
}

violation_3_13_4 contains msg if {
    not input.scp.shared_resource_controls
    msg := "3.13.4: Shared system resources are not controlled to prevent unauthorized data transfer"
}
violation_3_13_4 contains msg if {
    not input.scp.memory_protection_enabled
    msg := "3.13.4: Memory protection controls are not enabled (ASLR, DEP, etc.)"
}
violation_3_13_4 contains msg if {
    not input.scp.covert_channel_controls
    msg := "3.13.4: No controls to prevent covert channel information transfer via shared resources"
}

# 3.13.5 — Implement subnetworks for publicly accessible system components that
#           are physically or logically separated from internal networks. (L1)
default compliant_3_13_5 := false
compliant_3_13_5 if {
    input.scp.dmz_implemented == true
    input.scp.public_systems_isolated == true
    input.scp.cui_network_segregated == true
}

violation_3_13_5 contains msg if {
    not input.scp.dmz_implemented
    msg := "3.13.5: No DMZ or equivalent separation for publicly accessible system components"
}
violation_3_13_5 contains msg if {
    not input.scp.public_systems_isolated
    msg := "3.13.5: Publicly accessible systems are not physically or logically separated from internal networks"
}
violation_3_13_5 contains msg if {
    not input.scp.cui_network_segregated
    msg := "3.13.5: CUI systems are not segregated from publicly accessible system components"
}

# 3.13.6 — Deny network communications traffic by default and allow
#           communications by exception (i.e., deny all, permit by exception). (L2)
default compliant_3_13_6 := false
compliant_3_13_6 if {
    input.scp.default_deny_policy == true
    input.scp.explicit_allow_rules == true
    input.scp.firewall_rules_reviewed_annually == true
}

violation_3_13_6 contains msg if {
    not input.scp.default_deny_policy
    msg := "3.13.6: Network communications are not denied by default (permit-all policy in use)"
}
violation_3_13_6 contains msg if {
    not input.scp.explicit_allow_rules
    msg := "3.13.6: No explicit allow rules — communications are not permitted by exception"
}
violation_3_13_6 contains msg if {
    not input.scp.firewall_rules_reviewed_annually
    msg := "3.13.6: Firewall/network rules are not reviewed at least annually"
}

# 3.13.7 — Prevent remote devices from simultaneously connecting to the system
#           and to resources in other networks (i.e., split tunneling). (L2)
default compliant_3_13_7 := false
compliant_3_13_7 if {
    input.scp.split_tunneling_prevented == true
    input.scp.vpn_enforces_all_traffic == true
}

violation_3_13_7 contains msg if {
    not input.scp.split_tunneling_prevented
    msg := "3.13.7: Split tunneling is not prevented on VPN connections to CUI systems"
}
violation_3_13_7 contains msg if {
    not input.scp.vpn_enforces_all_traffic
    msg := "3.13.7: VPN configuration does not route all traffic through the secure tunnel"
}

# 3.13.8 — Implement cryptographic mechanisms to prevent unauthorized disclosure
#           of CUI during transmission unless otherwise protected. (L2)
default compliant_3_13_8 := false
compliant_3_13_8 if {
    input.scp.encryption_in_transit == true
    input.scp.fips_validated_tls == true
    input.scp.tls_min_version == "1.2"
}

violation_3_13_8 contains msg if {
    not input.scp.encryption_in_transit
    msg := "3.13.8: CUI is transmitted without cryptographic protection"
}
violation_3_13_8 contains msg if {
    not input.scp.fips_validated_tls
    msg := "3.13.8: Transmission encryption does not use FIPS-validated cryptographic modules"
}
violation_3_13_8 contains msg if {
    input.scp.tls_min_version != "1.2"
    input.scp.tls_min_version != "1.3"
    msg := sprintf("3.13.8: TLS minimum version is %v (must be TLS 1.2 or higher)", [input.scp.tls_min_version])
}

# 3.13.9 — Terminate network connections after a defined period of inactivity. (L2)
default compliant_3_13_9 := false
compliant_3_13_9 if {
    input.scp.session_timeout_enabled == true
    input.scp.network_session_timeout_minutes <= 30
}

violation_3_13_9 contains msg if {
    not input.scp.session_timeout_enabled
    msg := "3.13.9: Network sessions are not terminated after a period of inactivity"
}
violation_3_13_9 contains msg if {
    input.scp.network_session_timeout_minutes > 30
    msg := sprintf("3.13.9: Network session timeout is %v minutes (must be ≤30)", [input.scp.network_session_timeout_minutes])
}

# 3.13.10 — Establish and manage cryptographic keys when cryptography is
#            employed in organizational systems. (L2)
default compliant_3_13_10 := false
compliant_3_13_10 if {
    input.scp.key_management_policy == true
    input.scp.key_generation_secure == true
    input.scp.key_rotation_policy == true
    input.scp.key_storage_protected == true
}

violation_3_13_10 contains msg if {
    not input.scp.key_management_policy
    msg := "3.13.10: No cryptographic key management policy exists"
}
violation_3_13_10 contains msg if {
    not input.scp.key_generation_secure
    msg := "3.13.10: Cryptographic keys are not generated using approved, secure methods"
}
violation_3_13_10 contains msg if {
    not input.scp.key_rotation_policy
    msg := "3.13.10: No policy for rotating cryptographic keys on a defined schedule"
}
violation_3_13_10 contains msg if {
    not input.scp.key_storage_protected
    msg := "3.13.10: Cryptographic keys are not stored with appropriate access controls and protection"
}

# 3.13.11 — Employ FIPS-validated cryptography when used to protect the
#            confidentiality of CUI. (L2)
default compliant_3_13_11 := false
compliant_3_13_11 if {
    input.scp.fips_140_2_validated == true
    input.scp.non_fips_algorithms_prohibited == true
}

violation_3_13_11 contains msg if {
    not input.scp.fips_140_2_validated
    msg := "3.13.11: Cryptography protecting CUI confidentiality is not FIPS 140-2 validated"
}
violation_3_13_11 contains msg if {
    not input.scp.non_fips_algorithms_prohibited
    msg := "3.13.11: Non-FIPS cryptographic algorithms are not prohibited for CUI protection"
}

# 3.13.12 — Prohibit remote activation of collaborative computing devices and
#            provide indication of use to present users. (L2)
default compliant_3_13_12 := false
compliant_3_13_12 if {
    input.scp.remote_activation_prohibited == true
    input.scp.camera_mic_indicator_present == true
}

violation_3_13_12 contains msg if {
    not input.scp.remote_activation_prohibited
    msg := "3.13.12: Remote activation of cameras/microphones/collaborative devices is not prohibited"
}
violation_3_13_12 contains msg if {
    not input.scp.camera_mic_indicator_present
    msg := "3.13.12: No visual/audio indicator that cameras or microphones are active for present users"
}

# 3.13.13 — Control and monitor the use of mobile code. (L2)
default compliant_3_13_13 := false
compliant_3_13_13 if {
    input.scp.mobile_code_policy == true
    input.scp.unauthorized_mobile_code_blocked == true
    input.scp.mobile_code_usage_monitored == true
}

violation_3_13_13 contains msg if {
    not input.scp.mobile_code_policy
    msg := "3.13.13: No policy controlling the use of mobile code in CUI environments"
}
violation_3_13_13 contains msg if {
    not input.scp.unauthorized_mobile_code_blocked
    msg := "3.13.13: Unauthorized mobile code (JavaScript, ActiveX, etc.) is not blocked"
}
violation_3_13_13 contains msg if {
    not input.scp.mobile_code_usage_monitored
    msg := "3.13.13: Mobile code usage is not monitored in CUI systems"
}

# 3.13.14 — Control and monitor the use of VoIP technologies. (L2)
default compliant_3_13_14 := false
compliant_3_13_14 if {
    input.scp.voip_policy == true
    input.scp.voip_traffic_encrypted == true
    input.scp.voip_usage_monitored == true
}

violation_3_13_14 contains msg if {
    not input.scp.voip_policy
    msg := "3.13.14: No policy governing VoIP technology use in CUI environments"
}
violation_3_13_14 contains msg if {
    not input.scp.voip_traffic_encrypted
    msg := "3.13.14: VoIP traffic carrying CUI is not encrypted"
}
violation_3_13_14 contains msg if {
    not input.scp.voip_usage_monitored
    msg := "3.13.14: VoIP usage is not monitored in CUI system environments"
}

# 3.13.15 — Protect the authenticity of communications sessions. (L2)
default compliant_3_13_15 := false
compliant_3_13_15 if {
    input.scp.session_authentication_enforced == true
    input.scp.anti_replay_protection == true
    input.scp.session_hijacking_prevention == true
}

violation_3_13_15 contains msg if {
    not input.scp.session_authentication_enforced
    msg := "3.13.15: Communications session authenticity is not enforced"
}
violation_3_13_15 contains msg if {
    not input.scp.anti_replay_protection
    msg := "3.13.15: Anti-replay protection is not implemented for communications sessions"
}
violation_3_13_15 contains msg if {
    not input.scp.session_hijacking_prevention
    msg := "3.13.15: No controls to prevent session hijacking attacks"
}

# 3.13.16 — Protect CUI at rest. (L2)
default compliant_3_13_16 := false
compliant_3_13_16 if {
    input.scp.encryption_at_rest == true
    input.scp.fips_validated_storage_encryption == true
    input.scp.database_encryption_enabled == true
}

violation_3_13_16 contains msg if {
    not input.scp.encryption_at_rest
    msg := "3.13.16: CUI is not encrypted at rest"
}
violation_3_13_16 contains msg if {
    not input.scp.fips_validated_storage_encryption
    msg := "3.13.16: CUI at-rest encryption does not use FIPS-validated cryptographic modules"
}
violation_3_13_16 contains msg if {
    not input.scp.database_encryption_enabled
    msg := "3.13.16: Databases containing CUI are not encrypted"
}

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

all_violations_1_4 := array.concat(
    array.concat(
        [v | some v in violation_3_13_1],
        [v | some v in violation_3_13_2]
    ),
    array.concat(
        [v | some v in violation_3_13_3],
        [v | some v in violation_3_13_4]
    )
)

all_violations_5_8 := array.concat(
    array.concat(
        [v | some v in violation_3_13_5],
        [v | some v in violation_3_13_6]
    ),
    array.concat(
        [v | some v in violation_3_13_7],
        [v | some v in violation_3_13_8]
    )
)

all_violations_9_12 := array.concat(
    array.concat(
        [v | some v in violation_3_13_9],
        [v | some v in violation_3_13_10]
    ),
    array.concat(
        [v | some v in violation_3_13_11],
        [v | some v in violation_3_13_12]
    )
)

all_violations_13_16 := array.concat(
    array.concat(
        [v | some v in violation_3_13_13],
        [v | some v in violation_3_13_14]
    ),
    array.concat(
        [v | some v in violation_3_13_15],
        [v | some v in violation_3_13_16]
    )
)

all_violations := array.concat(
    array.concat(all_violations_1_4, all_violations_5_8),
    array.concat(all_violations_9_12, all_violations_13_16)
)

practices := [
    {"id": "3.13.1",  "level": 1, "compliant": compliant_3_13_1},
    {"id": "3.13.2",  "level": 2, "compliant": compliant_3_13_2},
    {"id": "3.13.3",  "level": 2, "compliant": compliant_3_13_3},
    {"id": "3.13.4",  "level": 2, "compliant": compliant_3_13_4},
    {"id": "3.13.5",  "level": 1, "compliant": compliant_3_13_5},
    {"id": "3.13.6",  "level": 2, "compliant": compliant_3_13_6},
    {"id": "3.13.7",  "level": 2, "compliant": compliant_3_13_7},
    {"id": "3.13.8",  "level": 2, "compliant": compliant_3_13_8},
    {"id": "3.13.9",  "level": 2, "compliant": compliant_3_13_9},
    {"id": "3.13.10", "level": 2, "compliant": compliant_3_13_10},
    {"id": "3.13.11", "level": 2, "compliant": compliant_3_13_11},
    {"id": "3.13.12", "level": 2, "compliant": compliant_3_13_12},
    {"id": "3.13.13", "level": 2, "compliant": compliant_3_13_13},
    {"id": "3.13.14", "level": 2, "compliant": compliant_3_13_14},
    {"id": "3.13.15", "level": 2, "compliant": compliant_3_13_15},
    {"id": "3.13.16", "level": 2, "compliant": compliant_3_13_16},
]

passing_count := count([p | some p in practices; p.compliant == true])

default compliant := false
compliant if count(all_violations) == 0

compliance_report := {
    "domain": "System and Communications Protection",
    "domain_id": "3.13",
    "total_practices": 16,
    "passing": passing_count,
    "failing": 16 - passing_count,
    "compliant": compliant,
    "violations": all_violations,
}
