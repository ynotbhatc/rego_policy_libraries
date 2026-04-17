package ncsc_caf.b5_resilience

import rego.v1

# NCSC Cyber Assessment Framework 4.0
# Objective B — Protecting Against Cyber Attack
# Principle B5 — Resilient Networks and Systems
#
# Contributing Outcomes covered:
#   B5.a — Resilience Preparation (BC/DR plans, exercises)
#   B5.b — Design for Resilience
#   B5.c — Backups
#
# Scoring: "achieved" | "partially_achieved" | "not_achieved"

# ---------------------------------------------------------------------------
# B5.a — Resilience Preparation
# IGPs: BC/DR plans documented for all essential functions, plans include
#       comms/escalation and recovery objectives (RTO/RPO), plans reviewed
#       annually, plans tested/exercised at defined frequency
# ---------------------------------------------------------------------------

default _b5a_plan_exists := false
_b5a_plan_exists if {
    input.resilience.bc_dr_plan.exists == true
}

default _b5a_plan_current := false
_b5a_plan_current if {
    input.resilience.bc_dr_plan.last_review_days <= 365
}

default _b5a_plan_acceptable_age := false
_b5a_plan_acceptable_age if {
    input.resilience.bc_dr_plan.last_review_days <= 730
}

default _b5a_covers_essential_functions := false
_b5a_covers_essential_functions if {
    input.resilience.bc_dr_plan.covers_essential_functions == true
}

default _b5a_tested := false
_b5a_tested if {
    input.resilience.bc_dr_plan.tested_days <= 365
}

default _b5a_rto_rpo_defined := false
_b5a_rto_rpo_defined if {
    input.resilience.bc_dr_plan.rto_rpo_defined == true
}

default _b5a_fully_achieved := false
_b5a_fully_achieved if {
    _b5a_plan_exists
    _b5a_plan_current
    _b5a_covers_essential_functions
    _b5a_tested
    _b5a_rto_rpo_defined
}

default _b5a_partially_achieved := false
_b5a_partially_achieved if {
    _b5a_plan_exists
    _b5a_plan_acceptable_age
    _b5a_covers_essential_functions
}

default co_b5a_achievement := "not_achieved"

co_b5a_achievement := "achieved" if { _b5a_fully_achieved }

co_b5a_achievement := "partially_achieved" if {
    not _b5a_fully_achieved
    _b5a_partially_achieved
}

co_b5a_details := {
    "plan_exists": _b5a_plan_exists,
    "last_review_days": object.get(input, ["resilience", "bc_dr_plan", "last_review_days"], 9999),
    "plan_current": _b5a_plan_current,
    "covers_essential_functions": _b5a_covers_essential_functions,
    "tested_days": object.get(input, ["resilience", "bc_dr_plan", "tested_days"], 9999),
    "tested_annually": _b5a_tested,
    "rto_rpo_defined": _b5a_rto_rpo_defined,
    "achievement": co_b5a_achievement,
}

# ---------------------------------------------------------------------------
# B5.b — Design for Resilience
# IGPs: Essential function systems physically and technically segregated from
#       business and external networks, resource limitations identified and
#       mitigated (no single points of failure), geographic/site redundancy,
#       no internet routing from critical systems
# ---------------------------------------------------------------------------

default _b5b_essential_fn_isolated := false
_b5b_essential_fn_isolated if {
    input.resilience.network_segregation.essential_function_isolated == true
}

default _b5b_business_system_separated := false
_b5b_business_system_separated if {
    input.resilience.network_segregation.business_system_separated == true
}

default _b5b_redundant_paths := false
_b5b_redundant_paths if {
    input.resilience.network_segregation.redundant_paths == true
}

default _b5b_no_internet_from_critical := false
_b5b_no_internet_from_critical if {
    input.resilience.network_segregation.no_internet_from_critical == true
}

default _b5b_geographic_redundancy := false
_b5b_geographic_redundancy if {
    input.resilience.network_segregation.geographic_redundancy == true
}

default _b5b_fully_achieved := false
_b5b_fully_achieved if {
    _b5b_essential_fn_isolated
    _b5b_business_system_separated
    _b5b_redundant_paths
    _b5b_no_internet_from_critical
    _b5b_geographic_redundancy
}

default _b5b_partially_achieved := false
_b5b_partially_achieved if {
    _b5b_essential_fn_isolated
    _b5b_business_system_separated
    _b5b_no_internet_from_critical
}

default co_b5b_achievement := "not_achieved"

co_b5b_achievement := "achieved" if { _b5b_fully_achieved }

co_b5b_achievement := "partially_achieved" if {
    not _b5b_fully_achieved
    _b5b_partially_achieved
}

co_b5b_details := {
    "essential_function_isolated": _b5b_essential_fn_isolated,
    "business_system_separated": _b5b_business_system_separated,
    "redundant_paths": _b5b_redundant_paths,
    "no_internet_from_critical": _b5b_no_internet_from_critical,
    "geographic_redundancy": _b5b_geographic_redundancy,
    "achievement": co_b5b_achievement,
}

# ---------------------------------------------------------------------------
# B5.c — Backups
# IGPs: Comprehensive automatic backups of all important data, backups secured
#       at a secondary site, resilient to ransomware (offline/air-gapped copy),
#       backup integrity verified, backups documented and routinely tested,
#       restoration tested at defined frequency
# ---------------------------------------------------------------------------

default _b5c_comprehensive_coverage := false
_b5c_comprehensive_coverage if {
    input.resilience.backups.comprehensive_coverage == true
}

default _b5c_automated := false
_b5c_automated if {
    input.resilience.backups.automated == true
}

default _b5c_backup_recent := false
_b5c_backup_recent if {
    input.resilience.backups.backup_age_hours <= 24
}

default _b5c_backup_acceptable_age := false
_b5c_backup_acceptable_age if {
    input.resilience.backups.backup_age_hours <= 168
}

default _b5c_offline_backup := false
_b5c_offline_backup if {
    input.resilience.backups.offline_backup_exists == true
}

default _b5c_ransomware_resilient := false
_b5c_ransomware_resilient if {
    input.resilience.backups.ransomware_resilient == true
}

default _b5c_restore_tested := false
_b5c_restore_tested if {
    input.resilience.backups.restore_test_age_days <= 30
}

default _b5c_restore_tested_annually := false
_b5c_restore_tested_annually if {
    input.resilience.backups.restore_test_age_days <= 365
}

default _b5c_fully_achieved := false
_b5c_fully_achieved if {
    _b5c_comprehensive_coverage
    _b5c_automated
    _b5c_backup_recent
    _b5c_offline_backup
    _b5c_ransomware_resilient
    _b5c_restore_tested
}

default _b5c_partially_achieved := false
_b5c_partially_achieved if {
    _b5c_automated
    _b5c_backup_acceptable_age
    _b5c_restore_tested_annually
}

default co_b5c_achievement := "not_achieved"

co_b5c_achievement := "achieved" if { _b5c_fully_achieved }

co_b5c_achievement := "partially_achieved" if {
    not _b5c_fully_achieved
    _b5c_partially_achieved
}

co_b5c_details := {
    "comprehensive_coverage": _b5c_comprehensive_coverage,
    "automated": _b5c_automated,
    "backup_age_hours": object.get(input, ["resilience", "backups", "backup_age_hours"], 9999),
    "backup_recent": _b5c_backup_recent,
    "offline_backup_exists": _b5c_offline_backup,
    "ransomware_resilient": _b5c_ransomware_resilient,
    "restore_test_age_days": object.get(input, ["resilience", "backups", "restore_test_age_days"], 9999),
    "restore_tested_recently": _b5c_restore_tested,
    "achievement": co_b5c_achievement,
}

# ---------------------------------------------------------------------------
# Objective-level rollup
# ---------------------------------------------------------------------------

default b5_compliant := false

b5_compliant if {
    co_b5a_achievement == "achieved"
    co_b5b_achievement == "achieved"
    co_b5c_achievement == "achieved"
}

b5_achievement_counts := {
    "achieved": count([co | some co in [co_b5a_achievement, co_b5b_achievement, co_b5c_achievement]; co == "achieved"]),
    "partially_achieved": count([co | some co in [co_b5a_achievement, co_b5b_achievement, co_b5c_achievement]; co == "partially_achieved"]),
    "not_achieved": count([co | some co in [co_b5a_achievement, co_b5b_achievement, co_b5c_achievement]; co == "not_achieved"]),
}

compliance_report := {
    "principle": "B5",
    "name": "Resilient Networks and Systems",
    "compliant": b5_compliant,
    "achievement_counts": b5_achievement_counts,
    "contributing_outcomes": {
        "B5.a": co_b5a_details,
        "B5.b": co_b5b_details,
        "B5.c": co_b5c_details,
    },
}
