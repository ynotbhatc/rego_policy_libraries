package ncsc_caf.c1_security_monitoring

import rego.v1

# NCSC Cyber Assessment Framework 4.0
# Objective C — Detecting Cyber Security Events
# Principle C1 — Security Monitoring
#
# Contributing Outcomes covered:
#   C1.a — Sources and Tools for Logging and Monitoring
#   C1.b — Securing Logs
#   C1.c — Generating Alerts
#   C1.d — Triage of Alerts
#   C1.f — Threat Intelligence
#
# Note: C1.e (Personnel Skills) is non-automatable and handled separately.
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
# C1.d — Triage of Alerts
# IGPs: Documented process for triaging security alerts, alerts reviewed
#       promptly with defined SLA, SOAR/ticketing integrated so no alerts
#       are missed, mean time to triage tracked, false positives tuned
# ---------------------------------------------------------------------------

default _c1d_process_documented := false
_c1d_process_documented if {
    input.security_monitoring.alert_triage.process_documented == true
}

default _c1d_mean_triage_fast := false
_c1d_mean_triage_fast if {
    input.security_monitoring.alert_triage.mean_triage_hours <= 4
}

default _c1d_mean_triage_acceptable := false
_c1d_mean_triage_acceptable if {
    input.security_monitoring.alert_triage.mean_triage_hours <= 24
}

default _c1d_ticketing_integrated := false
_c1d_ticketing_integrated if {
    input.security_monitoring.alert_triage.ticketing_integrated == true
}

default _c1d_sla_defined := false
_c1d_sla_defined if {
    input.security_monitoring.alert_triage.triage_sla_defined == true
}

default _c1d_fully_achieved := false
_c1d_fully_achieved if {
    _c1d_process_documented
    _c1d_mean_triage_fast
    _c1d_ticketing_integrated
    _c1d_sla_defined
}

default _c1d_partially_achieved := false
_c1d_partially_achieved if {
    _c1d_process_documented
    _c1d_mean_triage_acceptable
    _c1d_ticketing_integrated
}

default co_c1d_achievement := "not_achieved"

co_c1d_achievement := "achieved" if { _c1d_fully_achieved }

co_c1d_achievement := "partially_achieved" if {
    not _c1d_fully_achieved
    _c1d_partially_achieved
}

co_c1d_details := {
    "process_documented": _c1d_process_documented,
    "mean_triage_hours": object.get(input, ["security_monitoring", "alert_triage", "mean_triage_hours"], 9999),
    "mean_triage_fast": _c1d_mean_triage_fast,
    "ticketing_integrated": _c1d_ticketing_integrated,
    "triage_sla_defined": _c1d_sla_defined,
    "achievement": co_c1d_achievement,
}

# ---------------------------------------------------------------------------
# C1.f — Threat Intelligence
# IGPs: Threat intelligence feeds sourced from relevant, authoritative
#       sources (e.g., NCSC, ISACs), feeds reviewed regularly by analysts,
#       intelligence integrated with SIEM/detection tooling, feeds updated
#       at least daily
# ---------------------------------------------------------------------------

default _c1f_feeds_configured := false
_c1f_feeds_configured if {
    input.security_monitoring.threat_intel.feeds_configured == true
}

default _c1f_feed_count_sufficient := false
_c1f_feed_count_sufficient if {
    input.security_monitoring.threat_intel.feed_count >= 2
}

default _c1f_feeds_current := false
_c1f_feeds_current if {
    input.security_monitoring.threat_intel.last_update_hours <= 24
}

default _c1f_feeds_acceptable := false
_c1f_feeds_acceptable if {
    input.security_monitoring.threat_intel.last_update_hours <= 72
}

default _c1f_analyst_reviewed := false
_c1f_analyst_reviewed if {
    input.security_monitoring.threat_intel.analyst_reviewed == true
}

default _c1f_siem_integrated := false
_c1f_siem_integrated if {
    input.security_monitoring.threat_intel.integrated_with_siem == true
}

default _c1f_fully_achieved := false
_c1f_fully_achieved if {
    _c1f_feeds_configured
    _c1f_feed_count_sufficient
    _c1f_feeds_current
    _c1f_analyst_reviewed
    _c1f_siem_integrated
}

default _c1f_partially_achieved := false
_c1f_partially_achieved if {
    _c1f_feeds_configured
    _c1f_feeds_acceptable
}

default co_c1f_achievement := "not_achieved"

co_c1f_achievement := "achieved" if { _c1f_fully_achieved }

co_c1f_achievement := "partially_achieved" if {
    not _c1f_fully_achieved
    _c1f_partially_achieved
}

co_c1f_details := {
    "feeds_configured": _c1f_feeds_configured,
    "feed_count": object.get(input, ["security_monitoring", "threat_intel", "feed_count"], 0),
    "feed_count_sufficient": _c1f_feed_count_sufficient,
    "last_update_hours": object.get(input, ["security_monitoring", "threat_intel", "last_update_hours"], 9999),
    "feeds_current": _c1f_feeds_current,
    "analyst_reviewed": _c1f_analyst_reviewed,
    "siem_integrated": _c1f_siem_integrated,
    "achievement": co_c1f_achievement,
}

# ---------------------------------------------------------------------------
# Objective-level rollup
# ---------------------------------------------------------------------------

default c1_compliant := false

c1_compliant if {
    co_c1a_achievement == "achieved"
    co_c1b_achievement == "achieved"
    co_c1c_achievement == "achieved"
    co_c1d_achievement == "achieved"
    co_c1f_achievement == "achieved"
}

c1_achievement_counts := {
    "achieved": count([co | some co in [co_c1a_achievement, co_c1b_achievement, co_c1c_achievement, co_c1d_achievement, co_c1f_achievement]; co == "achieved"]),
    "partially_achieved": count([co | some co in [co_c1a_achievement, co_c1b_achievement, co_c1c_achievement, co_c1d_achievement, co_c1f_achievement]; co == "partially_achieved"]),
    "not_achieved": count([co | some co in [co_c1a_achievement, co_c1b_achievement, co_c1c_achievement, co_c1d_achievement, co_c1f_achievement]; co == "not_achieved"]),
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
        "C1.d": co_c1d_details,
        "C1.f": co_c1f_details,
    },
}
