package csa_ccm.incident_management

import rego.v1

default compliant := false

violations contains msg if {
    not input.csa_ccm.incident_management.ir_policy.policy_established
    msg := "SEF-01: Security incident response policy not formally established"
}

violations contains msg if {
    not input.csa_ccm.incident_management.ir_policy.cloud_incidents_in_scope
    msg := "SEF-01: Cloud security incidents not explicitly included in incident response policy scope"
}

violations contains msg if {
    not input.csa_ccm.incident_management.ir_policy.roles_defined
    msg := "SEF-01: Incident response roles and responsibilities not defined in policy"
}

violations contains msg if {
    not input.csa_ccm.incident_management.ir_policy.policy_reviewed_annually
    msg := "SEF-01: Incident response policy not reviewed and updated at least annually"
}

violations contains msg if {
    not input.csa_ccm.incident_management.ir_policy.ir_plan_exists
    msg := "SEF-01: Incident response plan not documented — detailed procedures for responding to security incidents required"
}

violations contains msg if {
    not input.csa_ccm.incident_management.classification.classification_scheme_defined
    msg := "SEF-02: Incident classification and severity scheme not defined"
}

violations contains msg if {
    not input.csa_ccm.incident_management.classification.severity_levels_documented
    msg := "SEF-02: Incident severity levels (critical, high, medium, low) not documented with clear criteria"
}

violations contains msg if {
    not input.csa_ccm.incident_management.classification.triage_procedure_defined
    msg := "SEF-02: Incident triage procedure not defined — method for assessing and classifying incoming incidents required"
}

violations contains msg if {
    not input.csa_ccm.incident_management.classification.cloud_specific_classification_included
    msg := "SEF-02: Cloud-specific incident types not included in classification scheme (account compromise, misconfiguration, data exposure)"
}

violations contains msg if {
    not input.csa_ccm.incident_management.escalation.escalation_procedures_defined
    msg := "SEF-03: Incident escalation procedures not defined — criteria and path for escalating incidents must be documented"
}

violations contains msg if {
    not input.csa_ccm.incident_management.escalation.escalation_contacts_maintained
    msg := "SEF-03: Escalation contact list not maintained with current information for all response roles"
}

violations contains msg if {
    not input.csa_ccm.incident_management.escalation.management_notification_thresholds
    msg := "SEF-03: Management notification thresholds not defined — criteria for when to notify leadership must be specified"
}

violations contains msg if {
    not input.csa_ccm.incident_management.escalation.on_call_rotation_established
    msg := "SEF-03: On-call rotation not established — 24/7 incident response coverage must be maintained"
}

violations contains msg if {
    not input.csa_ccm.incident_management.notification.customer_notification_procedure
    msg := "SEF-04: Customer notification procedure not defined for incidents affecting customer data or services"
}

violations contains msg if {
    not input.csa_ccm.incident_management.notification.regulatory_notification_timeframes
    msg := "SEF-04: Regulatory notification timeframes not documented — breach notification deadlines (e.g., GDPR 72 hours) must be tracked"
}

violations contains msg if {
    not input.csa_ccm.incident_management.notification.notification_templates_prepared
    msg := "SEF-04: Notification templates not prepared — pre-approved communications for stakeholders and regulators required"
}

violations contains msg if {
    not input.csa_ccm.incident_management.notification.notifications_sent_within_sla
    msg := "SEF-04: Incident notifications not sent within defined SLA timeframes for the incident severity level"
}

violations contains msg if {
    not input.csa_ccm.incident_management.forensic_readiness.forensic_readiness_plan_exists
    msg := "SEF-05: Forensic readiness plan not established — capability to collect and preserve evidence must be pre-planned"
}

violations contains msg if {
    not input.csa_ccm.incident_management.forensic_readiness.cloud_forensics_capability
    msg := "SEF-05: Cloud forensics capability not established — tools and procedures for cloud evidence collection must be ready"
}

violations contains msg if {
    not input.csa_ccm.incident_management.forensic_readiness.evidence_preservation_procedure
    msg := "SEF-05: Evidence preservation procedure not defined — chain of custody and evidence integrity must be maintained"
}

violations contains msg if {
    not input.csa_ccm.incident_management.forensic_readiness.legal_hold_integrated_with_ir
    msg := "SEF-05: Legal hold process not integrated with incident response — legal requirements during incidents must be addressed"
}

violations contains msg if {
    not input.csa_ccm.incident_management.forensic_readiness.log_retention_sufficient_for_forensics
    msg := "SEF-05: Log retention period not sufficient for forensic investigation — at least 12 months of logs must be available"
}

violations contains msg if {
    not input.csa_ccm.incident_management.post_incident_review.review_conducted
    msg := "SEF-06: Post-incident review not conducted after significant security incidents"
}

violations contains msg if {
    not input.csa_ccm.incident_management.post_incident_review.root_cause_analysis_performed
    msg := "SEF-06: Root cause analysis not performed for security incidents to prevent recurrence"
}

violations contains msg if {
    not input.csa_ccm.incident_management.post_incident_review.lessons_learned_documented
    msg := "SEF-06: Lessons learned not documented and shared from post-incident reviews"
}

violations contains msg if {
    not input.csa_ccm.incident_management.post_incident_review.process_improvements_tracked
    msg := "SEF-06: Process improvements identified in post-incident reviews not tracked to completion"
}

violations contains msg if {
    not input.csa_ccm.incident_management.ir_testing.ir_plan_tested
    msg := "SEF-06: Incident response plan not tested through exercises — tabletop or simulation exercises must be conducted"
}

violations contains msg if {
    not input.csa_ccm.incident_management.ediscovery.ediscovery_capability_defined
    msg := "SEF-07: E-discovery capability not defined — ability to identify and collect electronically stored information for legal proceedings required"
}

violations contains msg if {
    not input.csa_ccm.incident_management.ediscovery.cloud_data_searchable
    msg := "SEF-07: Cloud-stored data not searchable and exportable for e-discovery and legal proceedings"
}

violations contains msg if {
    not input.csa_ccm.incident_management.ediscovery.legal_team_engaged_in_planning
    msg := "SEF-07: Legal team not engaged in e-discovery capability planning — legal requirements must inform technical implementation"
}

violations contains msg if {
    not input.csa_ccm.incident_management.metrics.incident_metrics_tracked
    msg := "SEF-08: Security incident metrics not tracked — mean time to detect (MTTD) and mean time to respond (MTTR) must be measured"
}

violations contains msg if {
    not input.csa_ccm.incident_management.metrics.metrics_reported_to_management
    msg := "SEF-08: Incident metrics not regularly reported to management — leadership must have visibility into incident trends"
}

violations contains msg if {
    not input.csa_ccm.incident_management.metrics.trend_analysis_conducted
    msg := "SEF-08: Incident trend analysis not conducted to identify systemic issues or patterns"
}

compliant if { count(violations) == 0 }

compliance_report := {
    "domain": "SEF — Security Incident Management, E-Discovery & Cloud Forensics",
    "compliant": compliant,
    "violation_count": count(violations),
    "violations": violations,
}
