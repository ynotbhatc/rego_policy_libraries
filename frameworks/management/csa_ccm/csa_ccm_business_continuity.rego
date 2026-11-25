# METADATA
# title: "Csa Ccm Business Continuity"
# custom:
#   class: compliance
#   framework: csa_ccm
#   source: csa
#   domains: [cloud]
#   coverage:
#     checks: 43
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package csa_ccm.business_continuity

import rego.v1

default compliant := false

_base := ["csa_ccm", "business_continuity"]

# Evidence rule: only the boolean true passes a yes/no fact. A fact that is missing or null was not
# collected, and any other type (the strings "true" and "false", numbers) is a collection error. Both fail
# the check, and the finding names the problem. Boolean false keeps the plain finding text.
_fact(path) := object.get(_doc, array.concat(_base, path), null)

# No input document, or one that is not an object, reads as empty: every fact is then missing.
_doc := input if {
	is_object(input)
} else := {}

_field(path) := concat(".", array.concat(["input"], array.concat(_base, path)))

_finding(text, path) := text if _fact(path) == false

_finding(text, path) := sprintf("%s — evidence missing: %s not collected", [text, _field(path)]) if {
	_fact(path) == null
}

_finding(text, path) := sprintf("%s — evidence invalid: %s is not a boolean (got %s)", [text, _field(path), type_name(value)]) if {
	value := _fact(path)
	value != null
	not is_boolean(value)
}

violations contains msg if {
	msg := _finding("BCR-01: Business continuity management policy not formally established", ["bcm_policy", "policy_established"])
}

violations contains msg if {
	msg := _finding("BCR-01: Business continuity policy not approved by executive leadership", ["bcm_policy", "executive_approved"])
}

violations contains msg if {
	msg := _finding("BCR-01: Cloud services and dependencies not included in business continuity policy scope", ["bcm_policy", "cloud_services_included"])
}

violations contains msg if {
	msg := _finding("BCR-01: Business continuity policy not reviewed and updated at least annually", ["bcm_policy", "reviewed_annually"])
}

violations contains msg if {
	msg := _finding("BCR-02: Business impact analysis (BIA) not conducted — critical processes and dependencies must be identified", ["bia", "bia_conducted"])
}

violations contains msg if {
	msg := _finding("BCR-02: Critical business processes not identified and prioritized through BIA", ["bia", "critical_processes_identified"])
}

violations contains msg if {
	msg := _finding("BCR-02: Cloud service dependencies not mapped as part of business impact analysis", ["bia", "cloud_dependency_mapped"])
}

violations contains msg if {
	msg := _finding("BCR-02: BIA not reviewed after significant changes to business operations or technology", ["bia", "reviewed_after_significant_change"])
}

violations contains msg if {
	msg := _finding("BCR-03: Business continuity plans (BCPs) not documented for critical business functions", ["bcp", "plans_documented"])
}

violations contains msg if {
	msg := _finding("BCR-03: Business continuity plans not maintained and updated to reflect current operations", ["bcp", "plans_maintained"])
}

violations contains msg if {
	msg := _finding("BCR-03: Roles and responsibilities in BCPs not assigned to named individuals or teams", ["bcp", "roles_assigned"])
}

violations contains msg if {
	msg := _finding("BCR-03: Contact lists in BCPs not maintained with current information", ["bcp", "contact_lists_current"])
}

violations contains msg if {
	msg := _finding("BCR-03: BCP activation criteria and thresholds not clearly defined", ["bcp", "activation_criteria_defined"])
}

violations contains msg if {
	msg := _finding("BCR-04: Business continuity plans not tested at defined intervals", ["bcp_testing", "plans_tested"])
}

violations contains msg if {
	msg := _finding("BCR-04: BCP testing frequency does not meet defined schedule requirements", ["bcp_testing", "test_frequency_met"])
}

violations contains msg if {
	msg := _finding("BCR-04: BCP test results not documented including gaps and lessons learned", ["bcp_testing", "test_results_documented"])
}

violations contains msg if {
	msg := _finding("BCR-04: Deficiencies identified during BCP testing not tracked to remediation", ["bcp_testing", "deficiencies_remediated"])
}

violations contains msg if {
	msg := _finding("BCR-05: Disaster recovery plans (DRPs) not documented for critical IT systems", ["drp", "plans_documented"])
}

violations contains msg if {
	msg := _finding("BCR-05: Step-by-step recovery procedures not defined in disaster recovery plans", ["drp", "recovery_procedures_defined"])
}

violations contains msg if {
	msg := _finding("BCR-05: Alternate processing site or cloud failover target not defined in DRP", ["drp", "alternate_site_defined"])
}

violations contains msg if {
	msg := _finding("BCR-05: Data recovery procedures not included in disaster recovery plans", ["drp", "data_recovery_procedures_included"])
}

violations contains msg if {
	msg := _finding("BCR-06: Disaster recovery plans not tested at least annually", ["drp_testing", "drp_tested_annually"])
}

violations contains msg if {
	msg := _finding("BCR-06: Failover to alternate processing site or cloud region not tested", ["drp_testing", "failover_tested"])
}

violations contains msg if {
	msg := _finding("BCR-06: DRP test results not documented with outcomes, gaps, and corrective actions", ["drp_testing", "test_results_documented"])
}

violations contains msg if {
	msg := _finding("BCR-07: Critical technology and business dependencies not identified and managed", ["dependencies", "critical_dependencies_identified"])
}

violations contains msg if {
	msg := _finding("BCR-07: Third-party and cloud provider dependencies not mapped for continuity planning", ["dependencies", "third_party_dependencies_mapped"])
}

violations contains msg if {
	msg := _finding("BCR-07: Single points of failure in critical dependencies not identified and mitigated", ["dependencies", "single_points_of_failure_addressed"])
}

violations contains msg if {
	msg := _finding("BCR-08: Recovery time objectives (RTO) not defined for critical business functions and systems", ["rto_rpo", "rto_defined"])
}

violations contains msg if {
	msg := _finding("BCR-08: Recovery point objectives (RPO) not defined — acceptable data loss thresholds must be established", ["rto_rpo", "rpo_defined"])
}

violations contains msg if {
	msg := _finding("BCR-08: RTO and RPO targets not validated through testing to confirm achievability", ["rto_rpo", "rto_rpo_validated"])
}

violations contains msg if {
	msg := _finding("BCR-08: RTO and RPO targets not formally approved by business stakeholders", ["rto_rpo", "business_approved"])
}

violations contains msg if {
	msg := _finding("BCR-09: Backup procedures not implemented for critical systems and data", ["backup", "procedures_implemented"])
}

violations contains msg if {
	msg := _finding("BCR-09: Backup frequency does not meet defined recovery point objectives (RPO)", ["backup", "backup_frequency_meets_rpo"])
}

violations contains msg if {
	msg := _finding("BCR-09: Backup restoration not tested at defined intervals to verify recoverability", ["backup", "backups_tested"])
}

violations contains msg if {
	msg := _finding("BCR-09: Backups not stored offsite or in a separate cloud region from primary systems", ["backup", "offsite_or_cloud_storage"])
}

violations contains msg if {
	msg := _finding("BCR-09: Backup data not encrypted — backup storage must enforce encryption at rest", ["backup", "encryption_applied"])
}

violations contains msg if {
	msg := _finding("BCR-10: Crisis communication plan not established", ["crisis_communication", "plan_established"])
}

violations contains msg if {
	msg := _finding("BCR-10: Stakeholder notification procedures not defined in crisis communication plan", ["crisis_communication", "stakeholder_notifications_defined"])
}

violations contains msg if {
	msg := _finding("BCR-10: Media and public communications response procedures not defined for crisis events", ["crisis_communication", "media_response_defined"])
}

violations contains msg if {
	msg := _finding("BCR-10: Regulatory notification requirements not included in crisis communication plan", ["crisis_communication", "regulatory_notification_included"])
}

violations contains msg if {
	msg := _finding("BCR-11: Lessons learned process for incidents and BC/DR tests not formally defined", ["lessons_learned", "process_defined"])
}

violations contains msg if {
	msg := _finding("BCR-11: Lessons learned findings not incorporated into updated business continuity and DR plans", ["lessons_learned", "findings_incorporated_into_plans"])
}

violations contains msg if {
	msg := _finding("BCR-11: Post-incident or post-test review not conducted within required timeframe", ["lessons_learned", "review_conducted_after_events"])
}

compliant if count(violations) == 0

# The control ids this module carries checks for. A control can have several checks, so the report counts
# both: violations lists one finding per failed check, failed_controls counts the controls they belong to.
_control_ids := ["BCR-01", "BCR-02", "BCR-03", "BCR-04", "BCR-05", "BCR-06", "BCR-07", "BCR-08", "BCR-09", "BCR-10", "BCR-11"]

failed_control_ids := sort({id |
	some msg in violations
	id := split(msg, ":")[0]
})

compliance_report := {
	"domain": "BCR — Business Continuity Management & Operational Resilience",
	"compliant": compliant,
	"controls_checked": count(_control_ids),
	"failed_controls": count(failed_control_ids),
	"passed_controls": count(_control_ids) - count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"checks_total": 43,
	"violation_count": count(violations),
	"violations": violations,
}
