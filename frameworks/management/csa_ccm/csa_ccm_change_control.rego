package csa_ccm.change_control

import rego.v1

default compliant := false

violations contains msg if {
    not input.csa_ccm.change_control.change_policy.policy_established
    msg := "CCC-01: Change management policy not formally established"
}

violations contains msg if {
    not input.csa_ccm.change_control.change_policy.cloud_changes_in_scope
    msg := "CCC-01: Cloud environment changes not included in change management policy scope"
}

violations contains msg if {
    not input.csa_ccm.change_control.change_policy.policy_reviewed_annually
    msg := "CCC-01: Change management policy not reviewed and updated at least annually"
}

violations contains msg if {
    not input.csa_ccm.change_control.change_policy.roles_defined
    msg := "CCC-01: Roles and responsibilities for change management not defined in policy"
}

violations contains msg if {
    not input.csa_ccm.change_control.change_approval.documentation_required
    msg := "CCC-02: Change documentation not required before implementation — all changes must be formally documented"
}

violations contains msg if {
    not input.csa_ccm.change_control.change_approval.review_required
    msg := "CCC-02: Change review not required — changes must be reviewed by qualified personnel before approval"
}

violations contains msg if {
    not input.csa_ccm.change_control.change_approval.approval_required
    msg := "CCC-02: Formal change approval not required before implementation"
}

violations contains msg if {
    not input.csa_ccm.change_control.change_approval.change_records_maintained
    msg := "CCC-02: Change records not maintained — history of all changes must be retained for audit purposes"
}

violations contains msg if {
    not input.csa_ccm.change_control.change_approval.impact_assessment_required
    msg := "CCC-02: Impact assessment not required as part of change documentation and approval process"
}

violations contains msg if {
    not input.csa_ccm.change_control.emergency_change.procedure_defined
    msg := "CCC-03: Emergency change procedure not defined — expedited path for urgent changes must be documented"
}

violations contains msg if {
    not input.csa_ccm.change_control.emergency_change.post_approval_required
    msg := "CCC-03: Post-implementation approval not required for emergency changes implemented without prior approval"
}

violations contains msg if {
    not input.csa_ccm.change_control.emergency_change.emergency_changes_tracked
    msg := "CCC-03: Emergency changes not tracked separately for trend analysis and review"
}

violations contains msg if {
    not input.csa_ccm.change_control.emergency_change.retrospective_review_conducted
    msg := "CCC-03: Retrospective review not conducted for emergency changes to identify root cause and prevention"
}

violations contains msg if {
    not input.csa_ccm.change_control.config_baseline.baseline_established
    msg := "CCC-04: Configuration management baseline not established for cloud and on-premises systems"
}

violations contains msg if {
    not input.csa_ccm.change_control.config_baseline.baseline_documented
    msg := "CCC-04: Configuration baseline not documented — approved configuration state must be formally recorded"
}

violations contains msg if {
    not input.csa_ccm.change_control.config_baseline.baseline_reviewed_regularly
    msg := "CCC-04: Configuration baseline not reviewed regularly to ensure accuracy and relevance"
}

violations contains msg if {
    not input.csa_ccm.change_control.config_baseline.security_hardening_included
    msg := "CCC-04: Security hardening standards not included in configuration management baseline"
}

violations contains msg if {
    not input.csa_ccm.change_control.config_tracking.changes_tracked
    msg := "CCC-05: Configuration changes not tracked — all changes to baseline configurations must be recorded"
}

violations contains msg if {
    not input.csa_ccm.change_control.config_tracking.audit_trail_maintained
    msg := "CCC-05: Audit trail not maintained for configuration changes — who, what, when must be captured"
}

violations contains msg if {
    not input.csa_ccm.change_control.config_tracking.version_control_used
    msg := "CCC-05: Version control not used for configuration management artifacts"
}

violations contains msg if {
    not input.csa_ccm.change_control.unauthorized_change_detection.detection_controls_exist
    msg := "CCC-06: Unauthorized configuration change detection controls not implemented"
}

violations contains msg if {
    not input.csa_ccm.change_control.unauthorized_change_detection.alerts_configured
    msg := "CCC-06: Alerts not configured to notify security personnel of unauthorized configuration changes"
}

violations contains msg if {
    not input.csa_ccm.change_control.unauthorized_change_detection.drift_detection_automated
    msg := "CCC-06: Configuration drift detection not automated — manual-only detection is insufficient"
}

violations contains msg if {
    not input.csa_ccm.change_control.unauthorized_change_detection.response_procedure_defined
    msg := "CCC-06: Response procedure for unauthorized changes not defined — actions upon detection must be documented"
}

violations contains msg if {
    not input.csa_ccm.change_control.rollback.rollback_procedure_defined
    msg := "CCC-07: Rollback procedures not defined — method to reverse changes must be documented"
}

violations contains msg if {
    not input.csa_ccm.change_control.rollback.success_criteria_defined
    msg := "CCC-07: Change success criteria not defined — go/no-go decision points must be established before implementation"
}

violations contains msg if {
    not input.csa_ccm.change_control.rollback.rollback_tested
    msg := "CCC-07: Rollback procedures not tested to verify they can be executed successfully"
}

violations contains msg if {
    not input.csa_ccm.change_control.separation_of_duties.sod_enforced
    msg := "CCC-08: Separation of duties not enforced in change process — requester and approver must be different individuals"
}

violations contains msg if {
    not input.csa_ccm.change_control.separation_of_duties.developer_prod_access_restricted
    msg := "CCC-08: Developer access to production environment not restricted to prevent unauthorized changes"
}

violations contains msg if {
    not input.csa_ccm.change_control.separation_of_duties.approvals_auditable
    msg := "CCC-08: Change approvals not auditable — approval actions must be logged with identity and timestamp"
}

violations contains msg if {
    not input.csa_ccm.change_control.post_implementation_review.review_conducted
    msg := "CCC-09: Post-implementation review not conducted for significant changes"
}

violations contains msg if {
    not input.csa_ccm.change_control.post_implementation_review.objectives_validated
    msg := "CCC-09: Post-implementation review does not validate that change met its stated objectives"
}

violations contains msg if {
    not input.csa_ccm.change_control.post_implementation_review.unintended_effects_assessed
    msg := "CCC-09: Post-implementation review does not assess unintended effects or side effects of the change"
}

violations contains msg if {
    not input.csa_ccm.change_control.post_implementation_review.lessons_captured
    msg := "CCC-09: Lessons learned not captured from post-implementation reviews to improve future changes"
}

compliant if { count(violations) == 0 }

compliance_report := {
    "domain": "CCC — Change Control & Configuration Management",
    "compliant": compliant,
    "violation_count": count(violations),
    "violations": violations,
}
