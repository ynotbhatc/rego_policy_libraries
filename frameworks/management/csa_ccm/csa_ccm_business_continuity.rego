package csa_ccm.business_continuity

import rego.v1

default compliant := false

violations contains msg if {
    not input.csa_ccm.business_continuity.bcm_policy.policy_established
    msg := "BCR-01: Business continuity management policy not formally established"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.bcm_policy.executive_approved
    msg := "BCR-01: Business continuity policy not approved by executive leadership"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.bcm_policy.cloud_services_included
    msg := "BCR-01: Cloud services and dependencies not included in business continuity policy scope"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.bcm_policy.reviewed_annually
    msg := "BCR-01: Business continuity policy not reviewed and updated at least annually"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.bia.bia_conducted
    msg := "BCR-02: Business impact analysis (BIA) not conducted — critical processes and dependencies must be identified"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.bia.critical_processes_identified
    msg := "BCR-02: Critical business processes not identified and prioritized through BIA"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.bia.cloud_dependency_mapped
    msg := "BCR-02: Cloud service dependencies not mapped as part of business impact analysis"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.bia.reviewed_after_significant_change
    msg := "BCR-02: BIA not reviewed after significant changes to business operations or technology"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.bcp.plans_documented
    msg := "BCR-03: Business continuity plans (BCPs) not documented for critical business functions"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.bcp.plans_maintained
    msg := "BCR-03: Business continuity plans not maintained and updated to reflect current operations"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.bcp.roles_assigned
    msg := "BCR-03: Roles and responsibilities in BCPs not assigned to named individuals or teams"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.bcp.contact_lists_current
    msg := "BCR-03: Contact lists in BCPs not maintained with current information"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.bcp.activation_criteria_defined
    msg := "BCR-03: BCP activation criteria and thresholds not clearly defined"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.bcp_testing.plans_tested
    msg := "BCR-04: Business continuity plans not tested at defined intervals"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.bcp_testing.test_frequency_met
    msg := "BCR-04: BCP testing frequency does not meet defined schedule requirements"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.bcp_testing.test_results_documented
    msg := "BCR-04: BCP test results not documented including gaps and lessons learned"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.bcp_testing.deficiencies_remediated
    msg := "BCR-04: Deficiencies identified during BCP testing not tracked to remediation"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.drp.plans_documented
    msg := "BCR-05: Disaster recovery plans (DRPs) not documented for critical IT systems"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.drp.recovery_procedures_defined
    msg := "BCR-05: Step-by-step recovery procedures not defined in disaster recovery plans"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.drp.alternate_site_defined
    msg := "BCR-05: Alternate processing site or cloud failover target not defined in DRP"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.drp.data_recovery_procedures_included
    msg := "BCR-05: Data recovery procedures not included in disaster recovery plans"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.drp_testing.drp_tested_annually
    msg := "BCR-06: Disaster recovery plans not tested at least annually"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.drp_testing.failover_tested
    msg := "BCR-06: Failover to alternate processing site or cloud region not tested"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.drp_testing.test_results_documented
    msg := "BCR-06: DRP test results not documented with outcomes, gaps, and corrective actions"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.dependencies.critical_dependencies_identified
    msg := "BCR-07: Critical technology and business dependencies not identified and managed"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.dependencies.third_party_dependencies_mapped
    msg := "BCR-07: Third-party and cloud provider dependencies not mapped for continuity planning"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.dependencies.single_points_of_failure_addressed
    msg := "BCR-07: Single points of failure in critical dependencies not identified and mitigated"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.rto_rpo.rto_defined
    msg := "BCR-08: Recovery time objectives (RTO) not defined for critical business functions and systems"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.rto_rpo.rpo_defined
    msg := "BCR-08: Recovery point objectives (RPO) not defined — acceptable data loss thresholds must be established"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.rto_rpo.rto_rpo_validated
    msg := "BCR-08: RTO and RPO targets not validated through testing to confirm achievability"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.rto_rpo.business_approved
    msg := "BCR-08: RTO and RPO targets not formally approved by business stakeholders"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.backup.procedures_implemented
    msg := "BCR-09: Backup procedures not implemented for critical systems and data"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.backup.backup_frequency_meets_rpo
    msg := "BCR-09: Backup frequency does not meet defined recovery point objectives (RPO)"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.backup.backups_tested
    msg := "BCR-09: Backup restoration not tested at defined intervals to verify recoverability"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.backup.offsite_or_cloud_storage
    msg := "BCR-09: Backups not stored offsite or in a separate cloud region from primary systems"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.backup.encryption_applied
    msg := "BCR-09: Backup data not encrypted — backup storage must enforce encryption at rest"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.crisis_communication.plan_established
    msg := "BCR-10: Crisis communication plan not established"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.crisis_communication.stakeholder_notifications_defined
    msg := "BCR-10: Stakeholder notification procedures not defined in crisis communication plan"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.crisis_communication.media_response_defined
    msg := "BCR-10: Media and public communications response procedures not defined for crisis events"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.crisis_communication.regulatory_notification_included
    msg := "BCR-10: Regulatory notification requirements not included in crisis communication plan"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.lessons_learned.process_defined
    msg := "BCR-11: Lessons learned process for incidents and BC/DR tests not formally defined"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.lessons_learned.findings_incorporated_into_plans
    msg := "BCR-11: Lessons learned findings not incorporated into updated business continuity and DR plans"
}

violations contains msg if {
    not input.csa_ccm.business_continuity.lessons_learned.review_conducted_after_events
    msg := "BCR-11: Post-incident or post-test review not conducted within required timeframe"
}

compliant if { count(violations) == 0 }

compliance_report := {
    "domain": "BCR — Business Continuity Management & Operational Resilience",
    "compliant": compliant,
    "violation_count": count(violations),
    "violations": violations,
}
