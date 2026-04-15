package ncsc_caf.b2_identity_access

import rego.v1

# NCSC Cyber Assessment Framework 4.0
# Objective B — Protecting Against Cyber Attack
# Principle B2 — Identity and Access Control
#
# Contributing Outcomes covered:
#   B2.a — Identity Verification, Authentication and Authorisation
#   B2.b — Device Management
#   B2.c — Privileged User Management
#   B2.d — Identity and Access Management (IdAM)
#
# Scoring: "achieved" | "partially_achieved" | "not_achieved"
# Achieved: All Indicators of Good Practice (IGPs) met
# Partially Achieved: Core IGPs met but secondary IGPs missing
# Not Achieved: Core IGPs not met

# ---------------------------------------------------------------------------
# B2.a — Identity Verification, Authentication and Authorisation
# IGPs: MFA for all users, minimum necessary access, access review ≤ 6 months,
#       modern auth protocols (no NTLM/legacy), account provisioning process
# ---------------------------------------------------------------------------

default _b2a_mfa_all_users := false
_b2a_mfa_all_users if {
    input.identity_access.mfa_enforcement.enabled == true
    input.identity_access.mfa_enforcement.coverage == "all_users"
}

default _b2a_mfa_any := false
_b2a_mfa_any if {
    input.identity_access.mfa_enforcement.enabled == true
}

default _b2a_access_review_current := false
_b2a_access_review_current if {
    input.identity_access.account_review.last_review_days <= 180
}

default _b2a_modern_auth := false
_b2a_modern_auth if {
    input.identity_access.auth_protocols.ntlm_disabled == true
}

default _b2a_min_access := false
_b2a_min_access if {
    input.identity_access.min_access_enforced == true
}

default _b2a_fully_achieved := false
_b2a_fully_achieved if {
    _b2a_mfa_all_users
    _b2a_access_review_current
    _b2a_modern_auth
    _b2a_min_access
}

default _b2a_partially_achieved := false
_b2a_partially_achieved if {
    _b2a_mfa_any
}

default co_b2a_achievement := "not_achieved"

co_b2a_achievement := "achieved" if { _b2a_fully_achieved }

co_b2a_achievement := "partially_achieved" if {
    not _b2a_fully_achieved
    _b2a_partially_achieved
}

co_b2a_details := {
    "mfa_all_users": _b2a_mfa_all_users,
    "access_review_current": _b2a_access_review_current,
    "last_review_days": object.get(input, ["identity_access", "account_review", "last_review_days"], 9999),
    "modern_auth_protocols": _b2a_modern_auth,
    "min_access_enforced": _b2a_min_access,
    "achievement": co_b2a_achievement,
}

# ---------------------------------------------------------------------------
# B2.b — Device Management
# IGPs: MDM enrolment for all devices, certificate-based device identity,
#       PAW for privileged operations, regular unknown device scanning
# ---------------------------------------------------------------------------

default _b2b_mdm_deployed := false
_b2b_mdm_deployed if {
    input.device_management.mdm_deployed == true
}

default _b2b_mdm_coverage_full := false
_b2b_mdm_coverage_full if {
    input.device_management.mdm_enrollment_coverage_pct >= 95
}

default _b2b_mdm_coverage_partial := false
_b2b_mdm_coverage_partial if {
    input.device_management.mdm_enrollment_coverage_pct >= 70
}

default _b2b_cert_auth := false
_b2b_cert_auth if {
    input.device_management.certificate_auth == true
}

default _b2b_paw_enforced := false
_b2b_paw_enforced if {
    input.device_management.paw_enforced == true
}

default _b2b_unknown_device_scan := false
_b2b_unknown_device_scan if {
    input.device_management.unknown_device_scanning == true
}

default _b2b_fully_achieved := false
_b2b_fully_achieved if {
    _b2b_mdm_deployed
    _b2b_mdm_coverage_full
    _b2b_cert_auth
    _b2b_paw_enforced
    _b2b_unknown_device_scan
}

default _b2b_partially_achieved := false
_b2b_partially_achieved if {
    _b2b_mdm_deployed
    _b2b_mdm_coverage_partial
}

default co_b2b_achievement := "not_achieved"

co_b2b_achievement := "achieved" if { _b2b_fully_achieved }

co_b2b_achievement := "partially_achieved" if {
    not _b2b_fully_achieved
    _b2b_partially_achieved
}

co_b2b_details := {
    "mdm_deployed": _b2b_mdm_deployed,
    "mdm_enrollment_coverage_pct": object.get(input, ["device_management", "mdm_enrollment_coverage_pct"], 0),
    "certificate_auth": _b2b_cert_auth,
    "paw_enforced": _b2b_paw_enforced,
    "unknown_device_scanning": _b2b_unknown_device_scan,
    "achievement": co_b2b_achievement,
}

# ---------------------------------------------------------------------------
# B2.c — Privileged User Management
# IGPs: MFA on all privileged accounts, dedicated separate admin accounts,
#       time-bound/JIT access, activity logged for offline review,
#       joiners/movers/leavers automation
# ---------------------------------------------------------------------------

default _b2c_priv_mfa := false
_b2c_priv_mfa if {
    input.identity_access.mfa_enforcement.enabled == true
    input.identity_access.mfa_enforcement.privileged_mfa == true
}

default _b2c_dedicated_accounts := false
_b2c_dedicated_accounts if {
    input.identity_access.privileged_accounts.dedicated_accounts == true
}

default _b2c_time_bound_access := false
_b2c_time_bound_access if {
    input.identity_access.privileged_accounts.time_bound_access == true
}

default _b2c_activity_logged := false
_b2c_activity_logged if {
    input.identity_access.privileged_accounts.activity_logged == true
}

default _b2c_leavers_automated := false
_b2c_leavers_automated if {
    input.identity_access.privileged_accounts.leavers_automated == true
}

default _b2c_fully_achieved := false
_b2c_fully_achieved if {
    _b2c_priv_mfa
    _b2c_dedicated_accounts
    _b2c_time_bound_access
    _b2c_activity_logged
    _b2c_leavers_automated
}

default _b2c_partially_achieved := false
_b2c_partially_achieved if {
    _b2c_priv_mfa
    _b2c_dedicated_accounts
}

default co_b2c_achievement := "not_achieved"

co_b2c_achievement := "achieved" if { _b2c_fully_achieved }

co_b2c_achievement := "partially_achieved" if {
    not _b2c_fully_achieved
    _b2c_partially_achieved
}

co_b2c_details := {
    "privileged_mfa": _b2c_priv_mfa,
    "dedicated_accounts": _b2c_dedicated_accounts,
    "time_bound_access": _b2c_time_bound_access,
    "activity_logged": _b2c_activity_logged,
    "leavers_automated": _b2c_leavers_automated,
    "achievement": co_b2c_achievement,
}

# ---------------------------------------------------------------------------
# B2.d — Identity and Access Management (IdAM)
# IGPs: Minimum required access rights enforced, access revoked promptly on
#       departure/role change, all access logged and monitored, unauthorised
#       access alerts configured
# ---------------------------------------------------------------------------

default _b2d_min_access := false
_b2d_min_access if {
    input.identity_access.min_access_enforced == true
}

default _b2d_access_logs_monitored := false
_b2d_access_logs_monitored if {
    input.identity_access.access_logs.collected == true
    input.identity_access.access_logs.monitored == true
}

default _b2d_access_logs_collected := false
_b2d_access_logs_collected if {
    input.identity_access.access_logs.collected == true
}

default _b2d_unauth_alerts := false
_b2d_unauth_alerts if {
    input.identity_access.access_logs.unauth_access_alerts == true
}

default _b2d_access_revocation_prompt := false
_b2d_access_revocation_prompt if {
    input.identity_access.access_revocation.automated == true
}

default _b2d_fully_achieved := false
_b2d_fully_achieved if {
    _b2d_min_access
    _b2d_access_logs_monitored
    _b2d_unauth_alerts
    _b2d_access_revocation_prompt
}

default _b2d_partially_achieved := false
_b2d_partially_achieved if {
    _b2d_min_access
    _b2d_access_logs_collected
}

default co_b2d_achievement := "not_achieved"

co_b2d_achievement := "achieved" if { _b2d_fully_achieved }

co_b2d_achievement := "partially_achieved" if {
    not _b2d_fully_achieved
    _b2d_partially_achieved
}

co_b2d_details := {
    "min_access_enforced": _b2d_min_access,
    "access_logs_monitored": _b2d_access_logs_monitored,
    "unauth_access_alerts": _b2d_unauth_alerts,
    "access_revocation_automated": _b2d_access_revocation_prompt,
    "achievement": co_b2d_achievement,
}

# ---------------------------------------------------------------------------
# Objective-level rollup
# ---------------------------------------------------------------------------

# All COs must be achieved for the principle to be achieved
default b2_compliant := false

b2_compliant if {
    co_b2a_achievement == "achieved"
    co_b2b_achievement == "achieved"
    co_b2c_achievement == "achieved"
    co_b2d_achievement == "achieved"
}

b2_achievement_counts := {
    "achieved": count([co | some co in [co_b2a_achievement, co_b2b_achievement, co_b2c_achievement, co_b2d_achievement]; co == "achieved"]),
    "partially_achieved": count([co | some co in [co_b2a_achievement, co_b2b_achievement, co_b2c_achievement, co_b2d_achievement]; co == "partially_achieved"]),
    "not_achieved": count([co | some co in [co_b2a_achievement, co_b2b_achievement, co_b2c_achievement, co_b2d_achievement]; co == "not_achieved"]),
}

compliance_report := {
    "principle": "B2",
    "name": "Identity and Access Control",
    "compliant": b2_compliant,
    "achievement_counts": b2_achievement_counts,
    "contributing_outcomes": {
        "B2.a": co_b2a_details,
        "B2.b": co_b2b_details,
        "B2.c": co_b2c_details,
        "B2.d": co_b2d_details,
    },
}
