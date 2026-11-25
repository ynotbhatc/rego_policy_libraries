# METADATA
# title: "Csa Ccm Incident Management"
# custom:
#   class: compliance
#   framework: csa_ccm
#   source: csa
#   domains: [cloud]
#   coverage:
#     checks: 33
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package csa_ccm.incident_management

import rego.v1

default compliant := false

_base := ["csa_ccm", "incident_management"]

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
	msg := _finding("SEF-01: Security incident response policy not formally established", ["ir_policy", "policy_established"])
}

violations contains msg if {
	msg := _finding("SEF-01: Cloud security incidents not explicitly included in incident response policy scope", ["ir_policy", "cloud_incidents_in_scope"])
}

violations contains msg if {
	msg := _finding("SEF-01: Incident response roles and responsibilities not defined in policy", ["ir_policy", "roles_defined"])
}

violations contains msg if {
	msg := _finding("SEF-01: Incident response policy not reviewed and updated at least annually", ["ir_policy", "policy_reviewed_annually"])
}

violations contains msg if {
	msg := _finding("SEF-01: Incident response plan not documented — detailed procedures for responding to security incidents required", ["ir_policy", "ir_plan_exists"])
}

violations contains msg if {
	msg := _finding("SEF-02: Incident classification and severity scheme not defined", ["classification", "classification_scheme_defined"])
}

violations contains msg if {
	msg := _finding("SEF-02: Incident severity levels (critical, high, medium, low) not documented with clear criteria", ["classification", "severity_levels_documented"])
}

violations contains msg if {
	msg := _finding("SEF-02: Incident triage procedure not defined — method for assessing and classifying incoming incidents required", ["classification", "triage_procedure_defined"])
}

violations contains msg if {
	msg := _finding("SEF-02: Cloud-specific incident types not included in classification scheme (account compromise, misconfiguration, data exposure)", ["classification", "cloud_specific_classification_included"])
}

violations contains msg if {
	msg := _finding("SEF-03: Incident escalation procedures not defined — criteria and path for escalating incidents must be documented", ["escalation", "escalation_procedures_defined"])
}

violations contains msg if {
	msg := _finding("SEF-03: Escalation contact list not maintained with current information for all response roles", ["escalation", "escalation_contacts_maintained"])
}

violations contains msg if {
	msg := _finding("SEF-03: Management notification thresholds not defined — criteria for when to notify leadership must be specified", ["escalation", "management_notification_thresholds"])
}

violations contains msg if {
	msg := _finding("SEF-03: On-call rotation not established — 24/7 incident response coverage must be maintained", ["escalation", "on_call_rotation_established"])
}

violations contains msg if {
	msg := _finding("SEF-04: Customer notification procedure not defined for incidents affecting customer data or services", ["notification", "customer_notification_procedure"])
}

violations contains msg if {
	msg := _finding("SEF-04: Regulatory notification timeframes not documented — breach notification deadlines (e.g., GDPR 72 hours) must be tracked", ["notification", "regulatory_notification_timeframes"])
}

violations contains msg if {
	msg := _finding("SEF-04: Notification templates not prepared — pre-approved communications for stakeholders and regulators required", ["notification", "notification_templates_prepared"])
}

violations contains msg if {
	msg := _finding("SEF-04: Incident notifications not sent within defined SLA timeframes for the incident severity level", ["notification", "notifications_sent_within_sla"])
}

violations contains msg if {
	msg := _finding("SEF-05: Forensic readiness plan not established — capability to collect and preserve evidence must be pre-planned", ["forensic_readiness", "forensic_readiness_plan_exists"])
}

violations contains msg if {
	msg := _finding("SEF-05: Cloud forensics capability not established — tools and procedures for cloud evidence collection must be ready", ["forensic_readiness", "cloud_forensics_capability"])
}

violations contains msg if {
	msg := _finding("SEF-05: Evidence preservation procedure not defined — chain of custody and evidence integrity must be maintained", ["forensic_readiness", "evidence_preservation_procedure"])
}

violations contains msg if {
	msg := _finding("SEF-05: Legal hold process not integrated with incident response — legal requirements during incidents must be addressed", ["forensic_readiness", "legal_hold_integrated_with_ir"])
}

violations contains msg if {
	msg := _finding("SEF-05: Log retention period not sufficient for forensic investigation — at least 12 months of logs must be available", ["forensic_readiness", "log_retention_sufficient_for_forensics"])
}

violations contains msg if {
	msg := _finding("SEF-06: Post-incident review not conducted after significant security incidents", ["post_incident_review", "review_conducted"])
}

violations contains msg if {
	msg := _finding("SEF-06: Root cause analysis not performed for security incidents to prevent recurrence", ["post_incident_review", "root_cause_analysis_performed"])
}

violations contains msg if {
	msg := _finding("SEF-06: Lessons learned not documented and shared from post-incident reviews", ["post_incident_review", "lessons_learned_documented"])
}

violations contains msg if {
	msg := _finding("SEF-06: Process improvements identified in post-incident reviews not tracked to completion", ["post_incident_review", "process_improvements_tracked"])
}

violations contains msg if {
	msg := _finding("SEF-06: Incident response plan not tested through exercises — tabletop or simulation exercises must be conducted", ["ir_testing", "ir_plan_tested"])
}

violations contains msg if {
	msg := _finding("SEF-07: E-discovery capability not defined — ability to identify and collect electronically stored information for legal proceedings required", ["ediscovery", "ediscovery_capability_defined"])
}

violations contains msg if {
	msg := _finding("SEF-07: Cloud-stored data not searchable and exportable for e-discovery and legal proceedings", ["ediscovery", "cloud_data_searchable"])
}

violations contains msg if {
	msg := _finding("SEF-07: Legal team not engaged in e-discovery capability planning — legal requirements must inform technical implementation", ["ediscovery", "legal_team_engaged_in_planning"])
}

violations contains msg if {
	msg := _finding("SEF-08: Security incident metrics not tracked — mean time to detect (MTTD) and mean time to respond (MTTR) must be measured", ["metrics", "incident_metrics_tracked"])
}

violations contains msg if {
	msg := _finding("SEF-08: Incident metrics not regularly reported to management — leadership must have visibility into incident trends", ["metrics", "metrics_reported_to_management"])
}

violations contains msg if {
	msg := _finding("SEF-08: Incident trend analysis not conducted to identify systemic issues or patterns", ["metrics", "trend_analysis_conducted"])
}

compliant if count(violations) == 0

# The control ids this module carries checks for. A control can have several checks, so the report counts
# both: violations lists one finding per failed check, failed_controls counts the controls they belong to.
_control_ids := ["SEF-01", "SEF-02", "SEF-03", "SEF-04", "SEF-05", "SEF-06", "SEF-07", "SEF-08"]

failed_control_ids := sort({id |
	some msg in violations
	id := split(msg, ":")[0]
})

compliance_report := {
	"domain": "SEF — Security Incident Management, E-Discovery & Cloud Forensics",
	"compliant": compliant,
	"controls_checked": count(_control_ids),
	"failed_controls": count(failed_control_ids),
	"passed_controls": count(_control_ids) - count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"checks_total": 33,
	"violation_count": count(violations),
	"violations": violations,
}
