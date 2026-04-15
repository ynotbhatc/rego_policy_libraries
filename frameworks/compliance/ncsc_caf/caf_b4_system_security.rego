package ncsc_caf.b4_system_security

import rego.v1

# NCSC Cyber Assessment Framework 4.0
# Objective B — Protecting Against Cyber Attack
# Principle B4 — System Security
#
# Contributing Outcomes covered:
#   B4.a — Secure by Design (network segmentation, OT/IT separation)
#   B4.b — Secure Configuration (baseline, default accounts, allowlisting)
#   B4.c — Secure Management (PAW admin, malware protection)
#   B4.d — Vulnerability Management (patching, CVE exposure, EOL software)
#
# B4.b leverages CIS RHEL 9 compliance score already collected by AAC.
#
# Scoring: "achieved" | "partially_achieved" | "not_achieved"

# ---------------------------------------------------------------------------
# B4.a — Secure by Design
# IGPs: Network segmented into security zones, OT/critical systems isolated
#       from business and internet, DMZ at all external boundaries,
#       content-based attack mitigation at all inputs
# ---------------------------------------------------------------------------

default _b4a_ot_it_separated := false
_b4a_ot_it_separated if {
    input.system_security.network_segmentation.ot_it_separated == true
}

default _b4a_dmz_configured := false
_b4a_dmz_configured if {
    input.system_security.network_segmentation.dmz_configured == true
}

default _b4a_internet_blocked_from_critical := false
_b4a_internet_blocked_from_critical if {
    input.system_security.network_segmentation.internet_routing_blocked_from_critical == true
}

default _b4a_input_validation := false
_b4a_input_validation if {
    input.system_security.network_segmentation.input_validation_enforced == true
}

default _b4a_fully_achieved := false
_b4a_fully_achieved if {
    _b4a_ot_it_separated
    _b4a_dmz_configured
    _b4a_internet_blocked_from_critical
    _b4a_input_validation
}

default _b4a_partially_achieved := false
_b4a_partially_achieved if {
    _b4a_ot_it_separated
    _b4a_internet_blocked_from_critical
}

default co_b4a_achievement := "not_achieved"

co_b4a_achievement := "achieved" if { _b4a_fully_achieved }

co_b4a_achievement := "partially_achieved" if {
    not _b4a_fully_achieved
    _b4a_partially_achieved
}

co_b4a_details := {
    "ot_it_separated": _b4a_ot_it_separated,
    "dmz_configured": _b4a_dmz_configured,
    "internet_blocked_from_critical": _b4a_internet_blocked_from_critical,
    "input_validation_enforced": _b4a_input_validation,
    "achievement": co_b4a_achievement,
}

# ---------------------------------------------------------------------------
# B4.b — Secure Configuration
# IGPs: Defined baseline builds, default/shared/built-in accounts removed or
#       disabled, only permitted software installable, configurations regularly
#       validated, change management for security configurations.
#
# Leverages CIS RHEL 9 compliance score (already collected by AAC).
# Score thresholds: Achieved >= 90%, Partially >= 70%
# ---------------------------------------------------------------------------

default _b4b_cis_score_strong := false
_b4b_cis_score_strong if {
    input.system_security.secure_configuration.baseline_compliance_pct >= 90
}

default _b4b_cis_score_acceptable := false
_b4b_cis_score_acceptable if {
    input.system_security.secure_configuration.baseline_compliance_pct >= 70
}

default _b4b_default_accounts_disabled := false
_b4b_default_accounts_disabled if {
    input.system_security.secure_configuration.default_accounts_disabled == true
}

default _b4b_software_allowlisting := false
_b4b_software_allowlisting if {
    input.system_security.secure_configuration.software_allowlisting == true
}

default _b4b_config_drift_monitored := false
_b4b_config_drift_monitored if {
    input.system_security.secure_configuration.config_drift_monitoring == true
}

default _b4b_fully_achieved := false
_b4b_fully_achieved if {
    _b4b_cis_score_strong
    _b4b_default_accounts_disabled
    _b4b_software_allowlisting
    _b4b_config_drift_monitored
}

default _b4b_partially_achieved := false
_b4b_partially_achieved if {
    _b4b_cis_score_acceptable
    _b4b_default_accounts_disabled
}

default co_b4b_achievement := "not_achieved"

co_b4b_achievement := "achieved" if { _b4b_fully_achieved }

co_b4b_achievement := "partially_achieved" if {
    not _b4b_fully_achieved
    _b4b_partially_achieved
}

co_b4b_details := {
    "cis_baseline_compliance_pct": object.get(input, ["system_security", "secure_configuration", "baseline_compliance_pct"], 0),
    "cis_score_strong": _b4b_cis_score_strong,
    "default_accounts_disabled": _b4b_default_accounts_disabled,
    "software_allowlisting": _b4b_software_allowlisting,
    "config_drift_monitoring": _b4b_config_drift_monitored,
    "achievement": co_b4b_achievement,
}

# ---------------------------------------------------------------------------
# B4.c — Secure Management
# IGPs: Systems administered only from PAWs by authorised privileged users,
#       malware prevention deployed and current signatures,
#       technical documentation current and securely stored,
#       only authorised software installed
# ---------------------------------------------------------------------------

default _b4c_admin_from_paw := false
_b4c_admin_from_paw if {
    input.system_security.secure_management.admin_from_paw_only == true
}

default _b4c_malware_deployed := false
_b4c_malware_deployed if {
    input.system_security.secure_management.malware_protection == true
}

default _b4c_malware_signatures_current := false
_b4c_malware_signatures_current if {
    input.system_security.secure_management.malware_signatures_days <= 2
}

default _b4c_malware_signatures_acceptable := false
_b4c_malware_signatures_acceptable if {
    input.system_security.secure_management.malware_signatures_days <= 7
}

default _b4c_no_unauth_software := false
_b4c_no_unauth_software if {
    input.system_security.secure_management.unauthorised_software_count == 0
}

default _b4c_fully_achieved := false
_b4c_fully_achieved if {
    _b4c_admin_from_paw
    _b4c_malware_deployed
    _b4c_malware_signatures_current
    _b4c_no_unauth_software
}

default _b4c_partially_achieved := false
_b4c_partially_achieved if {
    _b4c_malware_deployed
    _b4c_malware_signatures_acceptable
}

default co_b4c_achievement := "not_achieved"

co_b4c_achievement := "achieved" if { _b4c_fully_achieved }

co_b4c_achievement := "partially_achieved" if {
    not _b4c_fully_achieved
    _b4c_partially_achieved
}

co_b4c_details := {
    "admin_from_paw_only": _b4c_admin_from_paw,
    "malware_protection_deployed": _b4c_malware_deployed,
    "malware_signatures_days": object.get(input, ["system_security", "secure_management", "malware_signatures_days"], 9999),
    "malware_signatures_current": _b4c_malware_signatures_current,
    "unauthorised_software_count": object.get(input, ["system_security", "secure_management", "unauthorised_software_count"], -1),
    "achievement": co_b4c_achievement,
}

# ---------------------------------------------------------------------------
# B4.d — Vulnerability Management
# IGPs: Current understanding of known vulnerabilities, all packages tracked
#       and patched promptly (critical within 14 days), regular penetration
#       testing, maximise use of supported software/firmware/hardware
# ---------------------------------------------------------------------------

default _b4d_critical_patches_current := false
_b4d_critical_patches_current if {
    input.system_security.vulnerability_management.critical_patch_age_days <= 14
}

default _b4d_critical_patches_acceptable := false
_b4d_critical_patches_acceptable if {
    input.system_security.vulnerability_management.critical_patch_age_days <= 30
}

default _b4d_vuln_scan_recent := false
_b4d_vuln_scan_recent if {
    input.system_security.vulnerability_management.vuln_scan_age_days <= 7
}

default _b4d_vuln_scan_acceptable := false
_b4d_vuln_scan_acceptable if {
    input.system_security.vulnerability_management.vuln_scan_age_days <= 30
}

default _b4d_no_eol_software := false
_b4d_no_eol_software if {
    input.system_security.vulnerability_management.eol_software_count == 0
}

default _b4d_eol_low := false
_b4d_eol_low if {
    input.system_security.vulnerability_management.eol_software_count <= 2
}

default _b4d_pentest_recent := false
_b4d_pentest_recent if {
    input.system_security.vulnerability_management.pentest_age_days <= 365
}

default _b4d_fully_achieved := false
_b4d_fully_achieved if {
    _b4d_critical_patches_current
    _b4d_vuln_scan_recent
    _b4d_no_eol_software
    _b4d_pentest_recent
}

default _b4d_partially_achieved := false
_b4d_partially_achieved if {
    _b4d_critical_patches_acceptable
    _b4d_vuln_scan_acceptable
    _b4d_eol_low
}

default co_b4d_achievement := "not_achieved"

co_b4d_achievement := "achieved" if { _b4d_fully_achieved }

co_b4d_achievement := "partially_achieved" if {
    not _b4d_fully_achieved
    _b4d_partially_achieved
}

co_b4d_details := {
    "critical_patch_age_days": object.get(input, ["system_security", "vulnerability_management", "critical_patch_age_days"], 9999),
    "patches_current": _b4d_critical_patches_current,
    "vuln_scan_age_days": object.get(input, ["system_security", "vulnerability_management", "vuln_scan_age_days"], 9999),
    "vuln_scan_recent": _b4d_vuln_scan_recent,
    "eol_software_count": object.get(input, ["system_security", "vulnerability_management", "eol_software_count"], -1),
    "no_eol_software": _b4d_no_eol_software,
    "pentest_age_days": object.get(input, ["system_security", "vulnerability_management", "pentest_age_days"], 9999),
    "pentest_recent": _b4d_pentest_recent,
    "achievement": co_b4d_achievement,
}

# ---------------------------------------------------------------------------
# Objective-level rollup
# ---------------------------------------------------------------------------

default b4_compliant := false

b4_compliant if {
    co_b4a_achievement == "achieved"
    co_b4b_achievement == "achieved"
    co_b4c_achievement == "achieved"
    co_b4d_achievement == "achieved"
}

b4_achievement_counts := {
    "achieved": count([co | some co in [co_b4a_achievement, co_b4b_achievement, co_b4c_achievement, co_b4d_achievement]; co == "achieved"]),
    "partially_achieved": count([co | some co in [co_b4a_achievement, co_b4b_achievement, co_b4c_achievement, co_b4d_achievement]; co == "partially_achieved"]),
    "not_achieved": count([co | some co in [co_b4a_achievement, co_b4b_achievement, co_b4c_achievement, co_b4d_achievement]; co == "not_achieved"]),
}

compliance_report := {
    "principle": "B4",
    "name": "System Security",
    "compliant": b4_compliant,
    "achievement_counts": b4_achievement_counts,
    "contributing_outcomes": {
        "B4.a": co_b4a_details,
        "B4.b": co_b4b_details,
        "B4.c": co_b4c_details,
        "B4.d": co_b4d_details,
    },
}
