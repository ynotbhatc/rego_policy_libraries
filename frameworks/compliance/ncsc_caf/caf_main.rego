package ncsc_caf.main

import rego.v1

import data.ncsc_caf.a3_asset_management
import data.ncsc_caf.b2_identity_access
import data.ncsc_caf.b3_data_security
import data.ncsc_caf.b4_system_security
import data.ncsc_caf.b5_resilience
import data.ncsc_caf.c1_security_monitoring
import data.ncsc_caf.d1_response_recovery

# NCSC Cyber Assessment Framework 4.0
# Master Orchestrator — Phase 1 + Phase 2
#
# Phase 1 (Technical Controls — 16 COs):
#   B2 (Identity & Access): B2.a, B2.b, B2.c, B2.d
#   B3 (Data Security):     B3.b, B3.c, B3.d
#   B4 (System Security):   B4.a, B4.b, B4.c, B4.d
#   B5 (Resilience):        B5.b, B5.c
#   C1 (Monitoring):        C1.a, C1.b, C1.c
#
# Phase 2 (Partially Automatable — 7 COs):
#   A3 (Asset Mgmt):        A3.a
#   B5 (Resilience):        B5.a
#   C1 (Monitoring):        C1.d, C1.f
#   D1 (Response):          D1.a, D1.b, D1.c
#
# OPA endpoint: POST http://192.168.4.62:8182/v1/data/ncsc_caf/main/compliance_report
#
# Three-tier scoring per CO: "achieved" | "partially_achieved" | "not_achieved"
# Overall compliant: all assessed COs must be "achieved"

# ---------------------------------------------------------------------------
# Overall compliance — all assessed principles must be achieved
# ---------------------------------------------------------------------------

default compliant := false

compliant if {
    a3_asset_management.a3_compliant
    b2_identity_access.b2_compliant
    b3_data_security.b3_compliant
    b4_system_security.b4_compliant
    b5_resilience.b5_compliant
    c1_security_monitoring.c1_compliant
    d1_response_recovery.d1_compliant
}

# ---------------------------------------------------------------------------
# CO inventory — all 23 COs with their achievement levels
# ---------------------------------------------------------------------------

all_co_achievements := {
    "A3.a": a3_asset_management.co_a3a_achievement,
    "B2.a": b2_identity_access.co_b2a_achievement,
    "B2.b": b2_identity_access.co_b2b_achievement,
    "B2.c": b2_identity_access.co_b2c_achievement,
    "B2.d": b2_identity_access.co_b2d_achievement,
    "B3.b": b3_data_security.co_b3b_achievement,
    "B3.c": b3_data_security.co_b3c_achievement,
    "B3.d": b3_data_security.co_b3d_achievement,
    "B4.a": b4_system_security.co_b4a_achievement,
    "B4.b": b4_system_security.co_b4b_achievement,
    "B4.c": b4_system_security.co_b4c_achievement,
    "B4.d": b4_system_security.co_b4d_achievement,
    "B5.a": b5_resilience.co_b5a_achievement,
    "B5.b": b5_resilience.co_b5b_achievement,
    "B5.c": b5_resilience.co_b5c_achievement,
    "C1.a": c1_security_monitoring.co_c1a_achievement,
    "C1.b": c1_security_monitoring.co_c1b_achievement,
    "C1.c": c1_security_monitoring.co_c1c_achievement,
    "C1.d": c1_security_monitoring.co_c1d_achievement,
    "C1.f": c1_security_monitoring.co_c1f_achievement,
    "D1.a": d1_response_recovery.co_d1a_achievement,
    "D1.b": d1_response_recovery.co_d1b_achievement,
    "D1.c": d1_response_recovery.co_d1c_achievement,
}

# ---------------------------------------------------------------------------
# Aggregate counts across all 23 COs
# ---------------------------------------------------------------------------

achieved_cos := [co | some co, status in all_co_achievements; status == "achieved"]
partially_achieved_cos := [co | some co, status in all_co_achievements; status == "partially_achieved"]
not_achieved_cos := [co | some co, status in all_co_achievements; status == "not_achieved"]

achievement_summary := {
    "total_cos_assessed": count(all_co_achievements),
    "achieved": count(achieved_cos),
    "partially_achieved": count(partially_achieved_cos),
    "not_achieved": count(not_achieved_cos),
    "achieved_list": achieved_cos,
    "partially_achieved_list": partially_achieved_cos,
    "not_achieved_list": not_achieved_cos,
}

# Percentage of COs at "achieved" level
achievement_pct := round((count(achieved_cos) / count(all_co_achievements)) * 100)

# ---------------------------------------------------------------------------
# Full compliance report
# ---------------------------------------------------------------------------

compliance_report := {
    "framework": "NCSC Cyber Assessment Framework 4.0",
    "version": "4.0",
    "phase": "Phase 1 + Phase 2",
    "scope": "23 Contributing Outcomes (16 technical + 7 organisational)",
    "compliant": compliant,
    "achievement_pct": achievement_pct,
    "achievement_summary": achievement_summary,
    "principles": {
        "A3_asset_management": a3_asset_management.compliance_report,
        "B2_identity_access": b2_identity_access.compliance_report,
        "B3_data_security": b3_data_security.compliance_report,
        "B4_system_security": b4_system_security.compliance_report,
        "B5_resilience": b5_resilience.compliance_report,
        "C1_security_monitoring": c1_security_monitoring.compliance_report,
        "D1_response_recovery": d1_response_recovery.compliance_report,
    },
    "not_achieved_cos": not_achieved_cos,
    "partially_achieved_cos": partially_achieved_cos,
}
