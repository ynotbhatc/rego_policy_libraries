package csa_ccm.audit_assurance

import rego.v1

default compliant := false

violations contains msg if {
    not input.csa_ccm.audit_assurance.independent_audit.program_established
    msg := "A&A-01: Independent audit and assurance program not formally established"
}

violations contains msg if {
    input.csa_ccm.audit_assurance.independent_audit.program_established
    not input.csa_ccm.audit_assurance.independent_audit.auditor_independence_confirmed
    msg := "A&A-01: Auditor independence not confirmed — internal auditors must have organizational independence"
}

violations contains msg if {
    input.csa_ccm.audit_assurance.independent_audit.program_established
    not input.csa_ccm.audit_assurance.independent_audit.cloud_scope_included
    msg := "A&A-01: Cloud services not included in the audit and assurance program scope"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.audit_scope.scope_documented
    msg := "A&A-02: Audit scope not documented — scope, objectives, and boundaries must be formally defined"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.audit_scope.frequency_defined
    msg := "A&A-02: Audit frequency not defined — schedule and cadence must be documented"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.audit_scope.methodology_documented
    msg := "A&A-02: Audit methodology not documented — assessment approach and standards must be specified"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.audit_scope.risk_based_approach
    msg := "A&A-02: Audit scope does not use a risk-based approach for prioritizing coverage"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.findings_tracking.remediation_tracked
    msg := "A&A-03: Audit findings not tracked to remediation — findings must be assigned, tracked, and closed"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.findings_tracking.owners_assigned
    msg := "A&A-03: Audit findings lack assigned owners responsible for remediation"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.findings_tracking.due_dates_set
    msg := "A&A-03: Audit findings lack remediation due dates — timelines must be established and monitored"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.findings_tracking.overdue_escalation_process
    msg := "A&A-03: No escalation process for overdue audit findings — escalation path must be defined"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.reporting.reports_communicated
    msg := "A&A-04: Audit reports not communicated to management and relevant stakeholders"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.reporting.executive_distribution
    msg := "A&A-04: Audit results not distributed to executive leadership for awareness and accountability"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.reporting.board_notification
    msg := "A&A-04: Board or audit committee not notified of significant audit findings"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.reporting.timely_issuance
    msg := "A&A-04: Audit reports not issued within required timeframe after audit completion"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.internal_audit.function_exists
    msg := "A&A-05: Internal audit function does not exist — a formal internal audit capability must be established"
}

violations contains msg if {
    input.csa_ccm.audit_assurance.internal_audit.function_exists
    not input.csa_ccm.audit_assurance.internal_audit.charter_documented
    msg := "A&A-05: Internal audit function lacks a formal charter defining scope, authority, and responsibilities"
}

violations contains msg if {
    input.csa_ccm.audit_assurance.internal_audit.function_exists
    not input.csa_ccm.audit_assurance.internal_audit.independence_maintained
    msg := "A&A-05: Internal audit function independence not maintained — must report outside of audited functions"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.evidence_retention.retention_policy_defined
    msg := "A&A-06: Audit evidence retention policy not defined — retention periods must align with regulatory requirements"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.evidence_retention.evidence_stored_securely
    msg := "A&A-06: Audit evidence not stored securely — integrity and confidentiality must be protected"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.evidence_retention.retention_period_met
    msg := "A&A-06: Audit evidence not retained for the required minimum retention period"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.evidence_retention.disposal_process_defined
    msg := "A&A-06: Secure disposal process for expired audit evidence not defined"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.continuous_monitoring.monitoring_program_exists
    msg := "A&A-07: Continuous compliance monitoring program not established"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.continuous_monitoring.automated_controls_monitored
    msg := "A&A-07: Automated controls not continuously monitored — technical controls require ongoing validation"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.continuous_monitoring.alerts_configured
    msg := "A&A-07: Compliance drift alerts not configured — deviations must trigger timely notification"
}

violations contains msg if {
    not input.csa_ccm.audit_assurance.continuous_monitoring.results_reviewed_regularly
    msg := "A&A-07: Continuous monitoring results not reviewed at defined intervals by responsible parties"
}

compliant if { count(violations) == 0 }

compliance_report := {
    "domain": "A&A — Audit and Assurance",
    "compliant": compliant,
    "violation_count": count(violations),
    "violations": violations,
}
