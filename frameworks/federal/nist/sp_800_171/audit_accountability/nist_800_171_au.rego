package nist.sp800_171.audit_accountability

import rego.v1

# NIST SP 800-171 Rev 3 - Audit and Accountability (AU) Requirements
# Family: 3.3 — Protecting Controlled Unclassified Information (CUI)

# 3.3.1: Create and retain system audit logs and records to the extent needed to enable
#         monitoring, analysis, investigation, and reporting of unlawful or unauthorized
#         system activity
default audit_logs_created_retained := false

audit_logs_created_retained if {
    input.nist_800_171.audit_accountability.audit_logs.logging_enabled == true
    input.nist_800_171.audit_accountability.audit_logs.retention_period_days >= 90
    input.nist_800_171.audit_accountability.audit_logs.covers_all_systems == true
}

# 3.3.2: Ensure that the actions of individual users can be uniquely traced to those users,
#         so they can be held accountable for their actions
default user_accountability := false

user_accountability if {
    input.nist_800_171.audit_accountability.user_tracing.unique_user_ids == true
    input.nist_800_171.audit_accountability.user_tracing.shared_accounts_prohibited == true
    input.nist_800_171.audit_accountability.user_tracing.audit_trail_complete == true
}

# 3.3.3: Review and update logged events
default logged_events_reviewed := false

logged_events_reviewed if {
    input.nist_800_171.audit_accountability.event_review.events_defined == true
    input.nist_800_171.audit_accountability.event_review.periodic_review_performed == true
    input.nist_800_171.audit_accountability.event_review.updates_documented == true
}

# 3.3.4: Alert in the event of an audit logging process failure
default audit_failure_alerting := false

audit_failure_alerting if {
    input.nist_800_171.audit_accountability.failure_alerting.alerts_configured == true
    input.nist_800_171.audit_accountability.failure_alerting.responsible_personnel_notified == true
    input.nist_800_171.audit_accountability.failure_alerting.response_procedures_documented == true
}

# 3.3.5: Correlate audit record review, analysis, and reporting processes for investigation
#         and response to indications of unlawful, unauthorized, suspicious, or unusual activity
default audit_correlation := false

audit_correlation if {
    input.nist_800_171.audit_accountability.correlation.correlation_capability == true
    input.nist_800_171.audit_accountability.correlation.cross_system_analysis == true
    input.nist_800_171.audit_accountability.correlation.reporting_integrated == true
}

# 3.3.6: Provide audit record reduction and report generation to support on-demand analysis
#         and reporting
default audit_reduction_reporting := false

audit_reduction_reporting if {
    input.nist_800_171.audit_accountability.reduction.reduction_capability == true
    input.nist_800_171.audit_accountability.reduction.report_generation == true
    input.nist_800_171.audit_accountability.reduction.on_demand_analysis == true
}

# 3.3.7: Provide a system capability that compares and synchronizes internal system clocks
#         with an authoritative source to generate time stamps for audit records
default time_synchronization := false

time_synchronization if {
    input.nist_800_171.audit_accountability.time_sync.ntp_configured == true
    input.nist_800_171.audit_accountability.time_sync.authoritative_source == true
    input.nist_800_171.audit_accountability.time_sync.all_systems_synchronized == true
}

# 3.3.8: Protect audit information and audit tools from unauthorized access, modification,
#         and deletion
default audit_protection := false

audit_protection if {
    input.nist_800_171.audit_accountability.audit_protection.access_restricted == true
    input.nist_800_171.audit_accountability.audit_protection.integrity_protected == true
    input.nist_800_171.audit_accountability.audit_protection.deletion_prevented == true
}

# 3.3.9: Limit management of audit logging to a subset of privileged users
default audit_management_limited := false

audit_management_limited if {
    input.nist_800_171.audit_accountability.audit_management.restricted_to_privileged == true
    input.nist_800_171.audit_accountability.audit_management.access_list_documented == true
    input.nist_800_171.audit_accountability.audit_management.separation_of_duties == true
}

# Violations set
violations contains msg if {
    not audit_logs_created_retained
    msg := "NIST 800-171 3.3.1: System audit logs must be created and retained (minimum 90 days) to support monitoring and investigation"
}

violations contains msg if {
    not user_accountability
    msg := "NIST 800-171 3.3.2: Individual user actions must be uniquely traceable; shared accounts must be prohibited"
}

violations contains msg if {
    not logged_events_reviewed
    msg := "NIST 800-171 3.3.3: Logged events must be defined, periodically reviewed, and updated as needed"
}

violations contains msg if {
    not audit_failure_alerting
    msg := "NIST 800-171 3.3.4: Alerts must be configured for audit logging process failures and responsible personnel must be notified"
}

violations contains msg if {
    not audit_correlation
    msg := "NIST 800-171 3.3.5: Audit records must be correlated across systems to support investigation of suspicious activity"
}

violations contains msg if {
    not audit_reduction_reporting
    msg := "NIST 800-171 3.3.6: Audit record reduction and report generation capability must be available for on-demand analysis"
}

violations contains msg if {
    not time_synchronization
    msg := "NIST 800-171 3.3.7: All system clocks must be synchronized with an authoritative NTP source for accurate audit timestamps"
}

violations contains msg if {
    not audit_protection
    msg := "NIST 800-171 3.3.8: Audit information and tools must be protected from unauthorized access, modification, and deletion"
}

violations contains msg if {
    not audit_management_limited
    msg := "NIST 800-171 3.3.9: Management of audit logging must be restricted to a subset of privileged users with documented access list"
}

# Compliance aggregation
default compliant := false

compliant if { count(violations) == 0 }

compliance_report := {
    "family": "3.3 Audit and Accountability",
    "standard": "NIST SP 800-171 Rev 3",
    "total_controls": 9,
    "violations": violations,
    "compliant": compliant,
    "controls": {
        "3.3.1_audit_logs_created_retained": audit_logs_created_retained,
        "3.3.2_user_accountability": user_accountability,
        "3.3.3_logged_events_reviewed": logged_events_reviewed,
        "3.3.4_audit_failure_alerting": audit_failure_alerting,
        "3.3.5_audit_correlation": audit_correlation,
        "3.3.6_audit_reduction_reporting": audit_reduction_reporting,
        "3.3.7_time_synchronization": time_synchronization,
        "3.3.8_audit_protection": audit_protection,
        "3.3.9_audit_management_limited": audit_management_limited,
    },
}
