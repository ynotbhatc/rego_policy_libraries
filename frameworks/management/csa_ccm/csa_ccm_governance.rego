# METADATA
# title: "Csa Ccm Governance"
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
#     as_of: v2.5.0
package csa_ccm.governance

import rego.v1

default compliant := false

_base := ["csa_ccm", "governance"]

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
	msg := _finding("GRC-01: Information security governance framework not formally established", ["security_framework", "framework_established"])
}

violations contains msg if {
	msg := _finding("GRC-01: Cloud computing governance not explicitly included in the security governance framework", ["security_framework", "cloud_governance_included"])
}

violations contains msg if {
	msg := _finding("GRC-01: Governance framework not aligned to a recognized standard (ISO 27001, NIST CSF, CSA CCM)", ["security_framework", "framework_aligned_to_standard"])
}

violations contains msg if {
	msg := _finding("GRC-01: Information security governance framework not formally documented and published", ["security_framework", "framework_documented"])
}

violations contains msg if {
	msg := _finding("GRC-01: Information security governance framework not reviewed at least annually", ["security_framework", "reviewed_annually"])
}

violations contains msg if {
	msg := _finding("GRC-02: CISO or equivalent cloud security leadership role not formally defined", ["roles_responsibilities", "ciso_or_equivalent_defined"])
}

violations contains msg if {
	msg := _finding("GRC-02: Roles and responsibilities for cloud security not documented and communicated", ["roles_responsibilities", "cloud_security_roles_documented"])
}

violations contains msg if {
	msg := _finding("GRC-02: Accountability for cloud security outcomes not assigned to named individuals or roles", ["roles_responsibilities", "accountability_assigned"])
}

violations contains msg if {
	msg := _finding("GRC-02: RACI or equivalent responsibility matrix not defined for cloud security functions", ["roles_responsibilities", "raci_or_equivalent_defined"])
}

violations contains msg if {
	msg := _finding("GRC-03: Risk management program not established for cloud and information security", ["risk_management", "risk_program_exists"])
}

violations contains msg if {
	msg := _finding("GRC-03: Risk register not maintained — identified risks must be documented with likelihood and impact", ["risk_management", "risk_register_maintained"])
}

violations contains msg if {
	msg := _finding("GRC-03: Risk treatment plans not defined for accepted or mitigated risks", ["risk_management", "risk_treatment_plans_defined"])
}

violations contains msg if {
	msg := _finding("GRC-03: Risk reviews not conducted at defined intervals — risk posture must be regularly reassessed", ["risk_management", "risk_review_cadence"])
}

violations contains msg if {
	msg := _finding("GRC-03: Risk management program not aligned to organizational business objectives and risk appetite", ["risk_management", "risk_aligned_to_business_objectives"])
}

violations contains msg if {
	msg := _finding("GRC-04: Compliance obligations not inventoried — all applicable legal, regulatory, and contractual requirements must be catalogued", ["compliance_obligations", "obligations_inventoried"])
}

violations contains msg if {
	msg := _finding("GRC-04: Compliance obligation status not tracked — adherence to each obligation must be monitored", ["compliance_obligations", "obligations_tracked"])
}

violations contains msg if {
	msg := _finding("GRC-04: Compliance gaps not identified and tracked to remediation", ["compliance_obligations", "gaps_identified_and_remediated"])
}

violations contains msg if {
	msg := _finding("GRC-04: Process not established to monitor for changes in applicable regulatory requirements", ["compliance_obligations", "regulatory_change_monitoring"])
}

violations contains msg if {
	msg := _finding("GRC-05: Cloud security policies not formally approved by executive leadership", ["executive_approval", "policies_executive_approved"])
}

violations contains msg if {
	msg := _finding("GRC-05: Cloud strategy not formally approved by executive leadership", ["executive_approval", "cloud_strategy_approved"])
}

violations contains msg if {
	msg := _finding("GRC-05: Security budget not allocated by executive leadership as part of approved strategy", ["executive_approval", "security_budget_allocated"])
}

violations contains msg if {
	msg := _finding("GRC-05: Board-level oversight of cloud security and risk management not established", ["executive_approval", "board_oversight_exists"])
}

violations contains msg if {
	msg := _finding("GRC-06: Security metrics and KPIs not defined for the cloud security program", ["metrics", "metrics_defined"])
}

violations contains msg if {
	msg := _finding("GRC-06: Security metrics not regularly reported to executive leadership and board", ["metrics", "metrics_reported_to_leadership"])
}

violations contains msg if {
	msg := _finding("GRC-06: Security metrics not actionable — metrics must drive decisions and program improvements", ["metrics", "metrics_actionable"])
}

violations contains msg if {
	msg := _finding("GRC-06: Security metrics and KPIs not reviewed regularly to assess relevance and effectiveness", ["metrics", "metrics_reviewed_regularly"])
}

compliant if count(violations) == 0

# The control ids this module carries checks for. A control can have several checks, so the report counts
# both: violations lists one finding per failed check, failed_controls counts the controls they belong to.
_control_ids := ["GRC-01", "GRC-02", "GRC-03", "GRC-04", "GRC-05", "GRC-06"]

failed_control_ids := sort({id |
	some msg in violations
	id := split(msg, ":")[0]
})

compliance_report := {
	"domain": "GRC — Governance, Risk & Compliance",
	"compliant": compliant,
	"controls_checked": count(_control_ids),
	"failed_controls": count(failed_control_ids),
	"passed_controls": count(_control_ids) - count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"checks_total": 26,
	"violation_count": count(violations),
	"violations": violations,
}
