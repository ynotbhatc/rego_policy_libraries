# METADATA
# title: "Csa Ccm Audit Assurance"
# custom:
#   class: compliance
#   framework: csa_ccm
#   source: csa
#   domains: [cloud]
#   coverage:
#     checks: 26
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package csa_ccm.audit_assurance

import rego.v1

default compliant := false

_base := ["csa_ccm", "audit_assurance"]

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
	msg := _finding("A&A-01: Independent audit and assurance program not formally established", ["independent_audit", "program_established"])
}

violations contains msg if {
	_fact(["independent_audit", "program_established"]) == true
	msg := _finding("A&A-01: Auditor independence not confirmed — internal auditors must have organizational independence", ["independent_audit", "auditor_independence_confirmed"])
}

violations contains msg if {
	_fact(["independent_audit", "program_established"]) == true
	msg := _finding("A&A-01: Cloud services not included in the audit and assurance program scope", ["independent_audit", "cloud_scope_included"])
}

violations contains msg if {
	msg := _finding("A&A-02: Audit scope not documented — scope, objectives, and boundaries must be formally defined", ["audit_scope", "scope_documented"])
}

violations contains msg if {
	msg := _finding("A&A-02: Audit frequency not defined — schedule and cadence must be documented", ["audit_scope", "frequency_defined"])
}

violations contains msg if {
	msg := _finding("A&A-02: Audit methodology not documented — assessment approach and standards must be specified", ["audit_scope", "methodology_documented"])
}

violations contains msg if {
	msg := _finding("A&A-02: Audit scope does not use a risk-based approach for prioritizing coverage", ["audit_scope", "risk_based_approach"])
}

violations contains msg if {
	msg := _finding("A&A-03: Audit findings not tracked to remediation — findings must be assigned, tracked, and closed", ["findings_tracking", "remediation_tracked"])
}

violations contains msg if {
	msg := _finding("A&A-03: Audit findings lack assigned owners responsible for remediation", ["findings_tracking", "owners_assigned"])
}

violations contains msg if {
	msg := _finding("A&A-03: Audit findings lack remediation due dates — timelines must be established and monitored", ["findings_tracking", "due_dates_set"])
}

violations contains msg if {
	msg := _finding("A&A-03: No escalation process for overdue audit findings — escalation path must be defined", ["findings_tracking", "overdue_escalation_process"])
}

violations contains msg if {
	msg := _finding("A&A-04: Audit reports not communicated to management and relevant stakeholders", ["reporting", "reports_communicated"])
}

violations contains msg if {
	msg := _finding("A&A-04: Audit results not distributed to executive leadership for awareness and accountability", ["reporting", "executive_distribution"])
}

violations contains msg if {
	msg := _finding("A&A-04: Board or audit committee not notified of significant audit findings", ["reporting", "board_notification"])
}

violations contains msg if {
	msg := _finding("A&A-04: Audit reports not issued within required timeframe after audit completion", ["reporting", "timely_issuance"])
}

violations contains msg if {
	msg := _finding("A&A-05: Internal audit function does not exist — a formal internal audit capability must be established", ["internal_audit", "function_exists"])
}

violations contains msg if {
	_fact(["internal_audit", "function_exists"]) == true
	msg := _finding("A&A-05: Internal audit function lacks a formal charter defining scope, authority, and responsibilities", ["internal_audit", "charter_documented"])
}

violations contains msg if {
	_fact(["internal_audit", "function_exists"]) == true
	msg := _finding("A&A-05: Internal audit function independence not maintained — must report outside of audited functions", ["internal_audit", "independence_maintained"])
}

violations contains msg if {
	msg := _finding("A&A-06: Audit evidence retention policy not defined — retention periods must align with regulatory requirements", ["evidence_retention", "retention_policy_defined"])
}

violations contains msg if {
	msg := _finding("A&A-06: Audit evidence not stored securely — integrity and confidentiality must be protected", ["evidence_retention", "evidence_stored_securely"])
}

violations contains msg if {
	msg := _finding("A&A-06: Audit evidence not retained for the required minimum retention period", ["evidence_retention", "retention_period_met"])
}

violations contains msg if {
	msg := _finding("A&A-06: Secure disposal process for expired audit evidence not defined", ["evidence_retention", "disposal_process_defined"])
}

violations contains msg if {
	msg := _finding("A&A-07: Continuous compliance monitoring program not established", ["continuous_monitoring", "monitoring_program_exists"])
}

violations contains msg if {
	msg := _finding("A&A-07: Automated controls not continuously monitored — technical controls require ongoing validation", ["continuous_monitoring", "automated_controls_monitored"])
}

violations contains msg if {
	msg := _finding("A&A-07: Compliance drift alerts not configured — deviations must trigger timely notification", ["continuous_monitoring", "alerts_configured"])
}

violations contains msg if {
	msg := _finding("A&A-07: Continuous monitoring results not reviewed at defined intervals by responsible parties", ["continuous_monitoring", "results_reviewed_regularly"])
}

compliant if count(violations) == 0

# The control ids this module carries checks for. A control can have several checks, so the report counts
# both: violations lists one finding per failed check, failed_controls counts the controls they belong to.
_control_ids := ["A&A-01", "A&A-02", "A&A-03", "A&A-04", "A&A-05", "A&A-06", "A&A-07"]

failed_control_ids := sort({id |
	some msg in violations
	id := split(msg, ":")[0]
})

compliance_report := {
	"domain": "A&A — Audit and Assurance",
	"compliant": compliant,
	"controls_checked": count(_control_ids),
	"failed_controls": count(failed_control_ids),
	"passed_controls": count(_control_ids) - count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"checks_total": 26,
	"violation_count": count(violations),
	"violations": violations,
}
