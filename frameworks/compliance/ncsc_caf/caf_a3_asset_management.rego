package ncsc_caf.a3_asset_management

import rego.v1

# NCSC Cyber Assessment Framework 4.0
# Objective A — Managing Security Risk
# Principle A3 — Asset Management
#
# Contributing Outcomes covered (automatable subset):
#   A3.a — Asset Management
#
# IGPs: Complete, accurate, up-to-date asset register covering all NIS
#       systems; assets classified by criticality; automated discovery in use;
#       register reconciled regularly against actual estate
#
# Scoring: "achieved" | "partially_achieved" | "not_achieved"

# ---------------------------------------------------------------------------
# A3.a — Asset Management
# ---------------------------------------------------------------------------

default _a3a_cmdb_exists := false
_a3a_cmdb_exists if {
    input.asset_management.cmdb_exists == true
}

default _a3a_coverage_strong := false
_a3a_coverage_strong if {
    input.asset_management.coverage_pct >= 95
}

default _a3a_coverage_acceptable := false
_a3a_coverage_acceptable if {
    input.asset_management.coverage_pct >= 80
}

default _a3a_audit_recent := false
_a3a_audit_recent if {
    input.asset_management.last_audit_days <= 30
}

default _a3a_audit_acceptable := false
_a3a_audit_acceptable if {
    input.asset_management.last_audit_days <= 90
}

default _a3a_automated_discovery := false
_a3a_automated_discovery if {
    input.asset_management.automated_discovery == true
}

default _a3a_critical_classified := false
_a3a_critical_classified if {
    input.asset_management.critical_assets_classified == true
}

default _a3a_fully_achieved := false
_a3a_fully_achieved if {
    _a3a_cmdb_exists
    _a3a_coverage_strong
    _a3a_audit_recent
    _a3a_automated_discovery
    _a3a_critical_classified
}

default _a3a_partially_achieved := false
_a3a_partially_achieved if {
    _a3a_cmdb_exists
    _a3a_coverage_acceptable
    _a3a_audit_acceptable
}

default co_a3a_achievement := "not_achieved"

co_a3a_achievement := "achieved" if { _a3a_fully_achieved }

co_a3a_achievement := "partially_achieved" if {
    not _a3a_fully_achieved
    _a3a_partially_achieved
}

co_a3a_details := {
    "cmdb_exists": _a3a_cmdb_exists,
    "coverage_pct": object.get(input, ["asset_management", "coverage_pct"], 0),
    "coverage_strong": _a3a_coverage_strong,
    "last_audit_days": object.get(input, ["asset_management", "last_audit_days"], 9999),
    "audit_recent": _a3a_audit_recent,
    "automated_discovery": _a3a_automated_discovery,
    "critical_assets_classified": _a3a_critical_classified,
    "achievement": co_a3a_achievement,
}

# ---------------------------------------------------------------------------
# Objective-level rollup
# ---------------------------------------------------------------------------

default a3_compliant := false

a3_compliant if {
    co_a3a_achievement == "achieved"
}

a3_achievement_counts := {
    "achieved": count([co | some co in [co_a3a_achievement]; co == "achieved"]),
    "partially_achieved": count([co | some co in [co_a3a_achievement]; co == "partially_achieved"]),
    "not_achieved": count([co | some co in [co_a3a_achievement]; co == "not_achieved"]),
}

compliance_report := {
    "principle": "A3",
    "name": "Asset Management",
    "compliant": a3_compliant,
    "achievement_counts": a3_achievement_counts,
    "contributing_outcomes": {
        "A3.a": co_a3a_details,
    },
}
