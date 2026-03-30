package cmmc.audit_accountability

import rego.v1

# =============================================================================
# CMMC 2.0 — Domain 3.3: Audit & Accountability
# NIST SP 800-171 Rev 2 — 9 Practices
# =============================================================================

# ---------------------------------------------------------------------------
# 3.3.1 — Create and retain system audit logs and records to the extent needed
#          to enable the monitoring, analysis, investigation, and reporting of
#          unlawful or unauthorized system activity. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_1 := false
compliant_3_3_1 if {
    input.audit.logging_enabled == true
    input.audit.log_retention_days >= 90
    input.audit.auditd_active == true
}

violation_3_3_1 contains msg if {
    not input.audit.logging_enabled
    msg := "3.3.1: System audit logging is not enabled"
}
violation_3_3_1 contains msg if {
    input.audit.log_retention_days < 90
    msg := sprintf("3.3.1: Audit log retention (%v days) is less than 90 days", [input.audit.log_retention_days])
}
violation_3_3_1 contains msg if {
    not input.audit.auditd_active
    msg := "3.3.1: auditd service is not active"
}

# ---------------------------------------------------------------------------
# 3.3.2 — Ensure that the actions of individual system users can be uniquely
#          traced to those users so they can be held accountable. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_2 := false
compliant_3_3_2 if {
    input.audit.user_activity_tracked == true
    input.audit.audit_rules_configured == true
    count(input.audit.privileged_command_rules) > 0
}

violation_3_3_2 contains msg if {
    not input.audit.user_activity_tracked
    msg := "3.3.2: Individual user activity is not uniquely tracked in audit logs"
}
violation_3_3_2 contains msg if {
    not input.audit.audit_rules_configured
    msg := "3.3.2: Audit rules are not configured to trace user actions"
}
violation_3_3_2 contains msg if {
    count(input.audit.privileged_command_rules) == 0
    msg := "3.3.2: No audit rules configured for privileged command execution"
}

# ---------------------------------------------------------------------------
# 3.3.3 — Review and update logged events. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_3 := false
compliant_3_3_3 if {
    input.audit.event_review_process == true
    input.audit.last_review_days_ago <= 365
}

violation_3_3_3 contains msg if {
    not input.audit.event_review_process
    msg := "3.3.3: No documented process for reviewing and updating logged audit events"
}
violation_3_3_3 contains msg if {
    input.audit.last_review_days_ago > 365
    msg := sprintf("3.3.3: Audit event review last performed %v days ago (must be annual)", [input.audit.last_review_days_ago])
}

# ---------------------------------------------------------------------------
# 3.3.4 — Alert in the event of audit logging process failures. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_4 := false
compliant_3_3_4 if {
    input.audit.failure_alerting_enabled == true
    input.audit.space_left_action != "ignore"
    input.audit.admin_space_left_action != "ignore"
}

violation_3_3_4 contains msg if {
    not input.audit.failure_alerting_enabled
    msg := "3.3.4: Alerting for audit log process failures is not configured"
}
violation_3_3_4 contains msg if {
    input.audit.space_left_action == "ignore"
    msg := "3.3.4: auditd space_left_action is set to 'ignore' — disk full events will not be alerted"
}
violation_3_3_4 contains msg if {
    input.audit.admin_space_left_action == "ignore"
    msg := "3.3.4: auditd admin_space_left_action is set to 'ignore' — critical disk events will not be alerted"
}

# ---------------------------------------------------------------------------
# 3.3.5 — Correlate audit record review, analysis, and reporting processes
#          for investigation and response. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_5 := false
compliant_3_3_5 if {
    input.audit.centralized_logging == true
    input.audit.siem_integrated == true
}

violation_3_3_5 contains msg if {
    not input.audit.centralized_logging
    msg := "3.3.5: Audit logs are not centralized — cannot correlate across systems"
}
violation_3_3_5 contains msg if {
    not input.audit.siem_integrated
    msg := "3.3.5: No SIEM or log correlation tool integrated for audit analysis"
}

# ---------------------------------------------------------------------------
# 3.3.6 — Provide audit record reduction and report generation to support
#          on-demand analysis and reporting. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_6 := false
compliant_3_3_6 if {
    input.audit.report_generation_capability == true
    input.audit.log_analysis_tool != ""
}

violation_3_3_6 contains msg if {
    not input.audit.report_generation_capability
    msg := "3.3.6: No capability for audit record reduction and report generation"
}
violation_3_3_6 contains msg if {
    input.audit.log_analysis_tool == ""
    msg := "3.3.6: No log analysis tool configured for on-demand audit reporting"
}

# ---------------------------------------------------------------------------
# 3.3.7 — Provide a system capability that compares and synchronizes internal
#          system clocks with an authoritative source. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_7 := false
compliant_3_3_7 if {
    input.audit.ntp_configured == true
    count(input.audit.ntp_servers) >= 1
    input.audit.time_sync_active == true
}

violation_3_3_7 contains msg if {
    not input.audit.ntp_configured
    msg := "3.3.7: NTP/chrony is not configured for clock synchronization"
}
violation_3_3_7 contains msg if {
    count(input.audit.ntp_servers) == 0
    msg := "3.3.7: No authoritative NTP time sources configured"
}
violation_3_3_7 contains msg if {
    not input.audit.time_sync_active
    msg := "3.3.7: Time synchronization service (chronyd/ntpd) is not active"
}

# ---------------------------------------------------------------------------
# 3.3.8 — Protect audit information and audit tools from unauthorized access,
#          modification, and deletion. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_8 := false
compliant_3_3_8 if {
    input.audit.log_file_permissions_correct == true
    input.audit.log_dir_permissions_correct == true
    input.audit.auditd_immutable_config == true
}

violation_3_3_8 contains msg if {
    not input.audit.log_file_permissions_correct
    msg := "3.3.8: Audit log file permissions allow unauthorized access"
}
violation_3_3_8 contains msg if {
    not input.audit.log_dir_permissions_correct
    msg := "3.3.8: Audit log directory permissions allow unauthorized access"
}
violation_3_3_8 contains msg if {
    not input.audit.auditd_immutable_config
    msg := "3.3.8: auditd configuration is not protected from modification (missing -e 2)"
}

# ---------------------------------------------------------------------------
# 3.3.9 — Limit management of audit logging to a subset of privileged users. (L2)
# ---------------------------------------------------------------------------

default compliant_3_3_9 := false
compliant_3_3_9 if {
    input.audit.management_restricted == true
    count(input.audit.audit_admins) > 0
    count(input.audit.audit_admins) <= 5
}

violation_3_3_9 contains msg if {
    not input.audit.management_restricted
    msg := "3.3.9: Audit log management is not restricted to privileged users"
}
violation_3_3_9 contains msg if {
    count(input.audit.audit_admins) == 0
    msg := "3.3.9: No designated privileged users for audit management"
}

# ---------------------------------------------------------------------------
# Aggregate compliance
# ---------------------------------------------------------------------------

all_violations := array.concat(
    array.concat(
        array.concat(
            [v | some v in violation_3_3_1],
            [v | some v in violation_3_3_2]
        ),
        array.concat(
            [v | some v in violation_3_3_3],
            [v | some v in violation_3_3_4]
        )
    ),
    array.concat(
        array.concat(
            [v | some v in violation_3_3_5],
            [v | some v in violation_3_3_6]
        ),
        array.concat(
            array.concat(
                [v | some v in violation_3_3_7],
                [v | some v in violation_3_3_8]
            ),
            [v | some v in violation_3_3_9]
        )
    )
)

practices := [
    {"id": "3.3.1", "level": 2, "compliant": compliant_3_3_1},
    {"id": "3.3.2", "level": 2, "compliant": compliant_3_3_2},
    {"id": "3.3.3", "level": 2, "compliant": compliant_3_3_3},
    {"id": "3.3.4", "level": 2, "compliant": compliant_3_3_4},
    {"id": "3.3.5", "level": 2, "compliant": compliant_3_3_5},
    {"id": "3.3.6", "level": 2, "compliant": compliant_3_3_6},
    {"id": "3.3.7", "level": 2, "compliant": compliant_3_3_7},
    {"id": "3.3.8", "level": 2, "compliant": compliant_3_3_8},
    {"id": "3.3.9", "level": 2, "compliant": compliant_3_3_9},
]

passing_count := count([p | some p in practices; p.compliant == true])

default compliant := false
compliant if count(all_violations) == 0

compliance_report := {
    "domain": "Audit & Accountability",
    "domain_id": "3.3",
    "total_practices": 9,
    "passing": passing_count,
    "failing": 9 - passing_count,
    "compliant": compliant,
    "violations": all_violations,
}
