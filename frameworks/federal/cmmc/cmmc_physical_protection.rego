package cmmc.physical_protection

import rego.v1

# =============================================================================
# CMMC 2.0 — Domain 3.10: Physical Protection
# NIST SP 800-171 Rev 2 — 6 Practices
# =============================================================================

# 3.10.1 — Limit physical access to organizational systems, equipment, and
#           respective operating environments to authorized individuals. (L1)
default compliant_3_10_1 := false
compliant_3_10_1 if {
    input.physical.access_control_implemented == true
    input.physical.authorized_personnel_list_maintained == true
    input.physical.physical_access_logs_kept == true
}

violation_3_10_1 contains msg if {
    not input.physical.access_control_implemented
    msg := "3.10.1: Physical access controls are not implemented for CUI systems/equipment"
}
violation_3_10_1 contains msg if {
    not input.physical.authorized_personnel_list_maintained
    msg := "3.10.1: No maintained list of individuals authorized for physical access"
}
violation_3_10_1 contains msg if {
    not input.physical.physical_access_logs_kept
    msg := "3.10.1: Physical access logs are not maintained"
}

# 3.10.2 — Protect and monitor the physical facility and support infrastructure
#           for organizational systems. (L1)
default compliant_3_10_2 := false
compliant_3_10_2 if {
    input.physical.facility_monitoring == true
    input.physical.cctv_or_equivalent == true
    input.physical.environmental_controls == true
}

violation_3_10_2 contains msg if {
    not input.physical.facility_monitoring
    msg := "3.10.2: Physical facility housing CUI systems is not monitored"
}
violation_3_10_2 contains msg if {
    not input.physical.cctv_or_equivalent
    msg := "3.10.2: No surveillance (CCTV or equivalent) protecting CUI facility"
}
violation_3_10_2 contains msg if {
    not input.physical.environmental_controls
    msg := "3.10.2: Environmental controls (temperature, humidity, fire suppression) not implemented"
}

# 3.10.3 — Escort visitors and monitor visitor activity. (L2)
default compliant_3_10_3 := false
compliant_3_10_3 if {
    input.physical.visitor_escort_required == true
    input.physical.visitor_log_maintained == true
    input.physical.visitor_badges_issued == true
}

violation_3_10_3 contains msg if {
    not input.physical.visitor_escort_required
    msg := "3.10.3: Visitors to CUI areas are not required to be escorted"
}
violation_3_10_3 contains msg if {
    not input.physical.visitor_log_maintained
    msg := "3.10.3: Visitor activity logs are not maintained"
}
violation_3_10_3 contains msg if {
    not input.physical.visitor_badges_issued
    msg := "3.10.3: Visitors are not issued distinguishing badges or credentials"
}

# 3.10.4 — Maintain audit logs of physical access. (L2)
default compliant_3_10_4 := false
compliant_3_10_4 if {
    input.physical.physical_access_audit_logs == true
    input.physical.access_log_retention_days >= 90
    input.physical.access_logs_reviewed_regularly == true
}

violation_3_10_4 contains msg if {
    not input.physical.physical_access_audit_logs
    msg := "3.10.4: Audit logs of physical access to CUI areas are not maintained"
}
violation_3_10_4 contains msg if {
    input.physical.access_log_retention_days < 90
    msg := sprintf("3.10.4: Physical access logs retained for %v days (minimum 90 days required)", [input.physical.access_log_retention_days])
}
violation_3_10_4 contains msg if {
    not input.physical.access_logs_reviewed_regularly
    msg := "3.10.4: Physical access audit logs are not reviewed on a regular basis"
}

# 3.10.5 — Control and manage physical access devices. (L2)
default compliant_3_10_5 := false
compliant_3_10_5 if {
    input.physical.access_devices_inventoried == true
    input.physical.lost_credentials_revoked == true
    input.physical.access_devices_audited_annually == true
}

violation_3_10_5 contains msg if {
    not input.physical.access_devices_inventoried
    msg := "3.10.5: Physical access devices (keycards, badges) are not inventoried"
}
violation_3_10_5 contains msg if {
    not input.physical.lost_credentials_revoked
    msg := "3.10.5: Lost or stolen physical access credentials are not immediately revoked"
}
violation_3_10_5 contains msg if {
    not input.physical.access_devices_audited_annually
    msg := "3.10.5: Physical access device inventory is not audited at least annually"
}

# 3.10.6 — Enforce safeguarding measures for CUI at alternate work sites. (L2)
default compliant_3_10_6 := false
compliant_3_10_6 if {
    input.physical.remote_work_policy == true
    input.physical.alternate_site_controls_defined == true
    input.physical.vpn_required_for_remote_cui_access == true
}

violation_3_10_6 contains msg if {
    not input.physical.remote_work_policy
    msg := "3.10.6: No policy for safeguarding CUI at alternate work sites (remote work)"
}
violation_3_10_6 contains msg if {
    not input.physical.alternate_site_controls_defined
    msg := "3.10.6: Physical and technical controls at alternate CUI sites are not defined"
}
violation_3_10_6 contains msg if {
    not input.physical.vpn_required_for_remote_cui_access
    msg := "3.10.6: VPN or equivalent is not required for CUI access at alternate sites"
}

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

all_violations := array.concat(
    array.concat(
        [v | some v in violation_3_10_1],
        [v | some v in violation_3_10_2]
    ),
    array.concat(
        array.concat(
            [v | some v in violation_3_10_3],
            [v | some v in violation_3_10_4]
        ),
        array.concat(
            [v | some v in violation_3_10_5],
            [v | some v in violation_3_10_6]
        )
    )
)

practices := [
    {"id": "3.10.1", "level": 1, "compliant": compliant_3_10_1},
    {"id": "3.10.2", "level": 1, "compliant": compliant_3_10_2},
    {"id": "3.10.3", "level": 2, "compliant": compliant_3_10_3},
    {"id": "3.10.4", "level": 2, "compliant": compliant_3_10_4},
    {"id": "3.10.5", "level": 2, "compliant": compliant_3_10_5},
    {"id": "3.10.6", "level": 2, "compliant": compliant_3_10_6},
]

passing_count := count([p | some p in practices; p.compliant == true])

default compliant := false
compliant if count(all_violations) == 0

compliance_report := {
    "domain": "Physical Protection",
    "domain_id": "3.10",
    "total_practices": 6,
    "passing": passing_count,
    "failing": 6 - passing_count,
    "compliant": compliant,
    "violations": all_violations,
}
