# METADATA
# title: "Csa Ccm Change Control"
# custom:
#   class: compliance
#   framework: csa_ccm
#   source: csa
#   domains: [cloud]
#   coverage:
#     checks: 34
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package csa_ccm.change_control

import rego.v1

default compliant := false

_base := ["csa_ccm", "change_control"]

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
	msg := _finding("CCC-01: Change management policy not formally established", ["change_policy", "policy_established"])
}

violations contains msg if {
	msg := _finding("CCC-01: Cloud environment changes not included in change management policy scope", ["change_policy", "cloud_changes_in_scope"])
}

violations contains msg if {
	msg := _finding("CCC-01: Change management policy not reviewed and updated at least annually", ["change_policy", "policy_reviewed_annually"])
}

violations contains msg if {
	msg := _finding("CCC-01: Roles and responsibilities for change management not defined in policy", ["change_policy", "roles_defined"])
}

violations contains msg if {
	msg := _finding("CCC-02: Change documentation not required before implementation — all changes must be formally documented", ["change_approval", "documentation_required"])
}

violations contains msg if {
	msg := _finding("CCC-02: Change review not required — changes must be reviewed by qualified personnel before approval", ["change_approval", "review_required"])
}

violations contains msg if {
	msg := _finding("CCC-02: Formal change approval not required before implementation", ["change_approval", "approval_required"])
}

violations contains msg if {
	msg := _finding("CCC-02: Change records not maintained — history of all changes must be retained for audit purposes", ["change_approval", "change_records_maintained"])
}

violations contains msg if {
	msg := _finding("CCC-02: Impact assessment not required as part of change documentation and approval process", ["change_approval", "impact_assessment_required"])
}

violations contains msg if {
	msg := _finding("CCC-03: Emergency change procedure not defined — expedited path for urgent changes must be documented", ["emergency_change", "procedure_defined"])
}

violations contains msg if {
	msg := _finding("CCC-03: Post-implementation approval not required for emergency changes implemented without prior approval", ["emergency_change", "post_approval_required"])
}

violations contains msg if {
	msg := _finding("CCC-03: Emergency changes not tracked separately for trend analysis and review", ["emergency_change", "emergency_changes_tracked"])
}

violations contains msg if {
	msg := _finding("CCC-03: Retrospective review not conducted for emergency changes to identify root cause and prevention", ["emergency_change", "retrospective_review_conducted"])
}

violations contains msg if {
	msg := _finding("CCC-04: Configuration management baseline not established for cloud and on-premises systems", ["config_baseline", "baseline_established"])
}

violations contains msg if {
	msg := _finding("CCC-04: Configuration baseline not documented — approved configuration state must be formally recorded", ["config_baseline", "baseline_documented"])
}

violations contains msg if {
	msg := _finding("CCC-04: Configuration baseline not reviewed regularly to ensure accuracy and relevance", ["config_baseline", "baseline_reviewed_regularly"])
}

violations contains msg if {
	msg := _finding("CCC-04: Security hardening standards not included in configuration management baseline", ["config_baseline", "security_hardening_included"])
}

violations contains msg if {
	msg := _finding("CCC-05: Configuration changes not tracked — all changes to baseline configurations must be recorded", ["config_tracking", "changes_tracked"])
}

violations contains msg if {
	msg := _finding("CCC-05: Audit trail not maintained for configuration changes — who, what, when must be captured", ["config_tracking", "audit_trail_maintained"])
}

violations contains msg if {
	msg := _finding("CCC-05: Version control not used for configuration management artifacts", ["config_tracking", "version_control_used"])
}

violations contains msg if {
	msg := _finding("CCC-06: Unauthorized configuration change detection controls not implemented", ["unauthorized_change_detection", "detection_controls_exist"])
}

violations contains msg if {
	msg := _finding("CCC-06: Alerts not configured to notify security personnel of unauthorized configuration changes", ["unauthorized_change_detection", "alerts_configured"])
}

violations contains msg if {
	msg := _finding("CCC-06: Configuration drift detection not automated — manual-only detection is insufficient", ["unauthorized_change_detection", "drift_detection_automated"])
}

violations contains msg if {
	msg := _finding("CCC-06: Response procedure for unauthorized changes not defined — actions upon detection must be documented", ["unauthorized_change_detection", "response_procedure_defined"])
}

violations contains msg if {
	msg := _finding("CCC-07: Rollback procedures not defined — method to reverse changes must be documented", ["rollback", "rollback_procedure_defined"])
}

violations contains msg if {
	msg := _finding("CCC-07: Change success criteria not defined — go/no-go decision points must be established before implementation", ["rollback", "success_criteria_defined"])
}

violations contains msg if {
	msg := _finding("CCC-07: Rollback procedures not tested to verify they can be executed successfully", ["rollback", "rollback_tested"])
}

violations contains msg if {
	msg := _finding("CCC-08: Separation of duties not enforced in change process — requester and approver must be different individuals", ["separation_of_duties", "sod_enforced"])
}

violations contains msg if {
	msg := _finding("CCC-08: Developer access to production environment not restricted to prevent unauthorized changes", ["separation_of_duties", "developer_prod_access_restricted"])
}

violations contains msg if {
	msg := _finding("CCC-08: Change approvals not auditable — approval actions must be logged with identity and timestamp", ["separation_of_duties", "approvals_auditable"])
}

violations contains msg if {
	msg := _finding("CCC-09: Post-implementation review not conducted for significant changes", ["post_implementation_review", "review_conducted"])
}

violations contains msg if {
	msg := _finding("CCC-09: Post-implementation review does not validate that change met its stated objectives", ["post_implementation_review", "objectives_validated"])
}

violations contains msg if {
	msg := _finding("CCC-09: Post-implementation review does not assess unintended effects or side effects of the change", ["post_implementation_review", "unintended_effects_assessed"])
}

violations contains msg if {
	msg := _finding("CCC-09: Lessons learned not captured from post-implementation reviews to improve future changes", ["post_implementation_review", "lessons_captured"])
}

compliant if count(violations) == 0

# The control ids this module carries checks for. A control can have several checks, so the report counts
# both: violations lists one finding per failed check, failed_controls counts the controls they belong to.
_control_ids := ["CCC-01", "CCC-02", "CCC-03", "CCC-04", "CCC-05", "CCC-06", "CCC-07", "CCC-08", "CCC-09"]

failed_control_ids := sort({id |
	some msg in violations
	id := split(msg, ":")[0]
})

compliance_report := {
	"domain": "CCC — Change Control & Configuration Management",
	"compliant": compliant,
	"controls_checked": count(_control_ids),
	"failed_controls": count(failed_control_ids),
	"passed_controls": count(_control_ids) - count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"checks_total": 34,
	"violation_count": count(violations),
	"violations": violations,
}
