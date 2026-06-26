package nist.sp800_53.audit_accountability

import rego.v1

# NIST SP 800-53 Rev 5 — Audit and Accountability (AU) Family
# Generation, protection, review, and analysis of audit records.

default compliant := false

violation contains msg if {
    not input.au_controls.policy.documented
    msg := "NIST AU-1: Audit and accountability policy not documented"
}

violation contains msg if {
    not input.au_controls.event_logging.enabled
    msg := "NIST AU-2: Auditable events not identified or logging not enabled"
}

violation contains msg if {
    not input.au_controls.content_of_records.adequate
    msg := "NIST AU-3: Audit record content lacks who/what/when/where/source/outcome"
}

violation contains msg if {
    not input.au_controls.storage_capacity.adequate
    msg := "NIST AU-4: Audit record storage capacity insufficient for required retention"
}

violation contains msg if {
    not input.au_controls.response_to_failures.alerting
    msg := "NIST AU-5: Audit logging failure does not alert appropriate personnel"
}

violation contains msg if {
    not input.au_controls.review_and_analysis.regular
    msg := "NIST AU-6: Audit records not regularly reviewed or analyzed"
}

violation contains msg if {
    not input.au_controls.reduction_and_reporting.tools_available
    msg := "NIST AU-7: Audit record reduction/report-generation tooling unavailable"
}

violation contains msg if {
    not input.au_controls.time_stamps.synchronized
    msg := "NIST AU-8: Audit record time stamps not synchronized to authoritative source"
}

violation contains msg if {
    not input.au_controls.protection_of_records.tamper_resistant
    msg := "NIST AU-9: Audit records not protected against unauthorized modification/deletion"
}

violation contains msg if {
    not input.au_controls.non_repudiation.implemented
    msg := "NIST AU-10: Non-repudiation of actions by individuals not implemented"
}

violation contains msg if {
    input.au_controls.retention_period_days < 365
    msg := sprintf("NIST AU-11: Audit record retention %d days is below 365-day minimum", [input.au_controls.retention_period_days])
}

violation contains msg if {
    not input.au_controls.generation.required_events_captured
    msg := "NIST AU-12: Audit record generation does not capture all required events"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "AU",
    "name":   "Audit and Accountability",
    "controls_evaluated": 12,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
