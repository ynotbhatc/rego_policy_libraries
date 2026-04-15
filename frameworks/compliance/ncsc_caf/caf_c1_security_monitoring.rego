package ncsc_caf.c1_security_monitoring

import rego.v1

# NCSC Cyber Assessment Framework 4.0
# Objective C — Detecting Cyber Security Events
# Principle C1 — Security Monitoring
#
# Contributing Outcomes covered (automatable subset):
#   C1.a — Sources and Tools for Logging and Monitoring
#   C1.b — Securing Logs
#   C1.c — Generating Alerts
#
# Note: C1.d (Triage of Alerts), C1.e (Personnel Skills), C1.f (Threat Intel)
# are partially/non-automatable and handled separately.
#
# Scoring: "achieved" | "partially_achieved" | "not_achieved"

# ---------------------------------------------------------------------------
# C1.a — Sources and Tools for Logging and Monitoring
# IGPs: Comprehensive monitoring of all NIS assets (host-based AND network),
#       all log sources synchronised to common time source (NTP),
#       monitoring strategy reviewed regularly, data enrichment applied
# ---------------------------------------------------------------------------

default _c1a_all_assets_covered := false
_c1a_all_assets_covered if {
    input.security_monitoring.log_sources.all_assets_covered == true
}

default _c1a_coverage_strong := false
_c1a_coverage_strong if {
    input.security_monitoring.log_sources.coverage_pct >= 95
}

default _c1a_coverage_acceptable := false
_c1a_coverage_acceptable if {
    input.security_monitoring.log_sources.coverage_pct >= 80
}

default _c1a_host_based_monitoring := false
_c1a_host_based_monitoring if {
    input.security_monitoring.log_sources.host_based_monitoring == true
}

default _c1a_network_monitoring := false
_c1a_network_monitoring if {
    input.security_monitoring.log_sources.network_monitoring == true
}

default _c1a_ntp_synchronised := false
_c1a_ntp_synchronised if {
    input.security_monitoring.ntp.synchronized == true
    input.security_monitoring.ntp.sources_consistent == true
}

default _c1a_ntp_partial := false
_c1a_ntp_partial if {
    input.security_monitoring.ntp.synchronized == true
}

default _c1a_fully_achieved := false
_c1a_fully_achieved if {
    _c1a_coverage_strong
    _c1a_host_based_monitoring
    _c1a_network_monitoring
    _c1a_ntp_synchronised
}

default _c1a_partially_achieved := false
_c1a_partially_achieved if {
    _c1a_coverage_acceptable
    _c1a_host_based_monitoring
    _c1a_ntp_partial
}

default co_c1a_achievement := "not_achieved"

co_c1a_achievement := "achieved" if { _c1a_fully_achieved }

co_c1a_achievement := "partially_achieved" if {
    not _c1a_fully_achieved
    _c1a_partially_achieved
}

co_c1a_details := {
    "log_coverage_pct": object.get(input, ["security_monitoring", "log_sources", "coverage_pct"], 0),
    "all_assets_covered": _c1a_all_assets_covered,
    "host_based_monitoring": _c1a_host_based_monitoring,
    "network_monitoring": _c1a_network_monitoring,
    "ntp_synchronised": _c1a_ntp_synchronised,
    "achievement": co_c1a_achievement,
}

# ---------------------------------------------------------------------------
# C1.b — Securing Logs
# IGPs: Log access restricted to business need, log integrity protected
#       (WORM or hash-chain), modification/deletion of logs detected and
#       attributed, analysis performed on copies not originals,
#       retention periods defined and enforced (min 12 months recommended)
# ---------------------------------------------------------------------------

default _c1b_access_restricted := false
_c1b_access_restricted if {
    input.security_monitoring.log_integrity.access_restricted == true
}

default _c1b_worm_or_append_only := false
_c1b_worm_or_append_only if {
    input.security_monitoring.log_integrity.worm_or_append_only == true
}

default _c1b_retention_adequate := false
_c1b_retention_adequate if {
    input.security_monitoring.log_integrity.retention_days >= 365
}

default _c1b_retention_partial := false
_c1b_retention_partial if {
    input.security_monitoring.log_integrity.retention_days >= 90
}

default _c1b_audit_trail := false
_c1b_audit_trail if {
    input.security_monitoring.log_integrity.audit_trail_enabled == true
}

default _c1b_fully_achieved := false
_c1b_fully_achieved if {
    _c1b_access_restricted
    _c1b_worm_or_append_only
    _c1b_retention_adequate
    _c1b_audit_trail
}

default _c1b_partially_achieved := false
_c1b_partially_achieved if {
    _c1b_access_restricted
    _c1b_retention_partial
}

default co_c1b_achievement := "not_achieved"

co_c1b_achievement := "achieved" if { _c1b_fully_achieved }

co_c1b_achievement := "partially_achieved" if {
    not _c1b_fully_achieved
    _c1b_partially_achieved
}

co_c1b_details := {
    "access_restricted": _c1b_access_restricted,
    "worm_or_append_only": _c1b_worm_or_append_only,
    "retention_days": object.get(input, ["security_monitoring", "log_integrity", "retention_days"], 0),
    "retention_adequate": _c1b_retention_adequate,
    "audit_trail_enabled": _c1b_audit_trail,
    "achievement": co_c1b_achievement,
}

# ---------------------------------------------------------------------------
# C1.c — Generating Alerts
# IGPs: All Indicators of Compromise (IoCs) detected promptly,
#       AV/IDS signatures applied within hours of release,
#       continuous monitoring (not periodic/batch only),
#       custom detection rules for environment-specific threats,
#       false positive tuning to reduce alert fatigue
# ---------------------------------------------------------------------------

default _c1c_ids_deployed := false
_c1c_ids_deployed if {
    input.security_monitoring.alerting.ids_deployed == true
}

default _c1c_signatures_current := false
_c1c_signatures_current if {
    input.security_monitoring.alerting.signature_age_hours <= 24
}

default _c1c_signatures_acceptable := false
_c1c_signatures_acceptable if {
    input.security_monitoring.alerting.signature_age_hours <= 72
}

default _c1c_ioc_feeds_integrated := false
_c1c_ioc_feeds_integrated if {
    input.security_monitoring.alerting.ioc_feeds_integrated == true
}

default _c1c_ioc_feeds_current := false
_c1c_ioc_feeds_current if {
    input.security_monitoring.alerting.ioc_feed_age_hours <= 24
}

default _c1c_ioc_feeds_acceptable := false
_c1c_ioc_feeds_acceptable if {
    input.security_monitoring.alerting.ioc_feed_age_hours <= 72
}

default _c1c_continuous_monitoring := false
_c1c_continuous_monitoring if {
    input.security_monitoring.alerting.continuous_monitoring == true
}

default _c1c_fully_achieved := false
_c1c_fully_achieved if {
    _c1c_ids_deployed
    _c1c_signatures_current
    _c1c_ioc_feeds_integrated
    _c1c_ioc_feeds_current
    _c1c_continuous_monitoring
}

default _c1c_partially_achieved := false
_c1c_partially_achieved if {
    _c1c_ids_deployed
    _c1c_signatures_acceptable
    _c1c_ioc_feeds_acceptable
}

default co_c1c_achievement := "not_achieved"

co_c1c_achievement := "achieved" if { _c1c_fully_achieved }

co_c1c_achievement := "partially_achieved" if {
    not _c1c_fully_achieved
    _c1c_partially_achieved
}

co_c1c_details := {
    "ids_deployed": _c1c_ids_deployed,
    "signature_age_hours": object.get(input, ["security_monitoring", "alerting", "signature_age_hours"], 9999),
    "signatures_current": _c1c_signatures_current,
    "ioc_feeds_integrated": _c1c_ioc_feeds_integrated,
    "ioc_feed_age_hours": object.get(input, ["security_monitoring", "alerting", "ioc_feed_age_hours"], 9999),
    "ioc_feeds_current": _c1c_ioc_feeds_current,
    "continuous_monitoring": _c1c_continuous_monitoring,
    "achievement": co_c1c_achievement,
}

# ---------------------------------------------------------------------------
# Objective-level rollup
# ---------------------------------------------------------------------------

default c1_compliant := false

c1_compliant if {
    co_c1a_achievement == "achieved"
    co_c1b_achievement == "achieved"
    co_c1c_achievement == "achieved"
}

c1_achievement_counts := {
    "achieved": count([co | some co in [co_c1a_achievement, co_c1b_achievement, co_c1c_achievement]; co == "achieved"]),
    "partially_achieved": count([co | some co in [co_c1a_achievement, co_c1b_achievement, co_c1c_achievement]; co == "partially_achieved"]),
    "not_achieved": count([co | some co in [co_c1a_achievement, co_c1b_achievement, co_c1c_achievement]; co == "not_achieved"]),
}

compliance_report := {
    "principle": "C1",
    "name": "Security Monitoring",
    "compliant": c1_compliant,
    "achievement_counts": c1_achievement_counts,
    "contributing_outcomes": {
        "C1.a": co_c1a_details,
        "C1.b": co_c1b_details,
        "C1.c": co_c1c_details,
    },
}
