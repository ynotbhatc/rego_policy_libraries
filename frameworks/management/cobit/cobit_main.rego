# METADATA
# title: "COBIT 2019 — Governance and Management of Enterprise I&T (ISACA)"
# custom:
#   class: compliance
#   framework: cobit
#   source: isaca
#   domains: [it-governance]
#   coverage:
#     checks: 18
#     cited: 18
#     expected: 18
#     found: 18
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cobit.main

import rego.v1

# COBIT 2019 — Governance and Management of Enterprise I&T (ISACA)
#
# COBIT 7 — BLOCKED BY VENDOR. ISACA published COBIT 7 on 2026-11-19 and
# requires a paid commercial licence to embed COBIT 7 content, objectives
# or derived material in software, with no exception for free or
# open-source use. This library is free and takes no licence that costs
# money, so the module stays on COBIT 2019 and COBIT 7 is not planned.
#
# SCOPE — read before quoting this to anyone: COBIT is a
# governance PROCESS and MATURITY framework, not a technical control
# catalog. Most of it (capability levels, design factors, goals
# cascade) is not machine-assessable, and no tool that claims to
# "assess COBIT" from configuration state is telling the whole truth.
# What CAN be attested is the EXISTENCE and operation of the
# governance system COBIT prescribes: that the governance/management
# objectives have owners, artifacts, and review cadences. That is what
# this module does — attestation-level checks across the five domains
# (EDM, APO, BAI, DSS, MEA) at objective-cluster granularity.
#
# The technical substance behind DSS05 (security services) and
# APO13 (security management) is assessed by this library's actual
# control frameworks (ISO 27001, NIST CSF, CIS benchmarks) — pair
# this module with those; do not treat it as a security assessment.
#
# Input contract: entity-level attestation. See tests.

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Evidence rule (bad input never passes, issue #301) ───────────────────────
# A yes/no fact passes only as the boolean true. A fact that is missing, null,
# a string such as "true" / "false" / "no", or a number is an evidence problem:
# the control fails and the finding says which ("evidence missing: <field> not
# collected" / "evidence invalid: <field> is not a boolean (got string)").
# Where a control accepts alternatives, any one alternative that is true
# satisfies it, but an alternative of the wrong type fails it: the verdict
# never rests on mistyped evidence.

_absent := "__absent__"

_value(path) := object.get(input, path, _absent)

_yes(path) if _value(path) == true

_collected(path) if _value(path) != _absent

_mistyped(path) if {
	_collected(path)
	not is_boolean(_value(path))
}

_unmet(facts) if {
	every path in facts {
		not _yes(path)
	}
}

_unmet(facts) if {
	some path in facts
	_mistyped(path)
}

_problem(path) := sprintf("evidence missing: input.%s not collected", [concat(".", path)]) if not _collected(path)

_problem(path) := sprintf("evidence invalid: input.%s is not a boolean (got %s)", [concat(".", path), type_name(_value(path))]) if _mistyped(path)

_evidence(facts) := sprintf(" [%s]", [concat("; ", problems)]) if {
	problems := [_problem(path) | some path in facts]
	count(problems) > 0
} else := ""

# ── EDM — Evaluate, Direct and Monitor (governance) ──────────────────────────

violations contains msg if {
	facts := [["edm", "governance_framework_established"]]
	_unmet(facts)
	msg := sprintf("COBIT EDM01: Governance framework for enterprise I&T not established and maintained by the governing body%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["edm", "benefits_delivery_overseen"]]
	_unmet(facts)
	msg := sprintf("COBIT EDM02: Benefits delivery from I&T investments not evaluated, directed, and monitored%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["edm", "risk_optimization_overseen"]]
	_unmet(facts)
	msg := sprintf("COBIT EDM03: I&T risk appetite not defined and risk optimization not overseen by the governing body%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["edm", "resource_optimization_overseen"]]
	_unmet(facts)
	msg := sprintf("COBIT EDM04: I&T resource optimization (people, process, technology) not overseen%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["edm", "stakeholder_engagement"]]
	_unmet(facts)
	msg := sprintf("COBIT EDM05: Stakeholder engagement and transparent I&T reporting not directed and monitored%s", [_evidence(facts)])
}

# ── APO — Align, Plan and Organize ───────────────────────────────────────────

violations contains msg if {
	facts := [["apo", "it_strategy_documented"]]
	_unmet(facts)
	msg := sprintf("COBIT APO02: I&T strategy aligned to enterprise goals not documented and maintained%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["apo", "enterprise_architecture_managed"]]
	_unmet(facts)
	msg := sprintf("COBIT APO03: Enterprise architecture not managed%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["apo", "risk_management_operated"]]
	_unmet(facts)
	msg := sprintf("COBIT APO12: I&T risk management process not operated (identify, assess, respond, monitor)%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["apo", "security_management_defined"]]
	_unmet(facts)
	msg := sprintf("COBIT APO13: Information security management system not defined and operated (see ISO 27001 module for ISMS technical depth)%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["apo", "vendor_management_operated"]]
	_unmet(facts)
	msg := sprintf("COBIT APO10: Vendor/third-party service management not operated%s", [_evidence(facts)])
}

# ── BAI — Build, Acquire and Implement ───────────────────────────────────────

violations contains msg if {
	facts := [["bai", "change_management_operated"]]
	_unmet(facts)
	msg := sprintf("COBIT BAI06: I&T change management process not operated%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["bai", "configuration_management_operated"]]
	_unmet(facts)
	msg := sprintf("COBIT BAI10: Configuration management (asset/CI baseline and tracking) not operated%s", [_evidence(facts)])
}

# ── DSS — Deliver, Service and Support ───────────────────────────────────────

violations contains msg if {
	facts := [["dss", "operations_managed"]]
	_unmet(facts)
	msg := sprintf("COBIT DSS01: I&T operations management not performed to defined procedures%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["dss", "incident_management_operated"]]
	_unmet(facts)
	msg := sprintf("COBIT DSS02: Service request and incident management process not operated%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["dss", "security_services_delivered"]]
	_unmet(facts)
	msg := sprintf("COBIT DSS05: Security services not delivered and monitored (see NIST CSF / CIS modules for the technical assessment behind this objective)%s", [_evidence(facts)])
}

# ── MEA — Monitor, Evaluate and Assess ───────────────────────────────────────

violations contains msg if {
	facts := [["mea", "performance_monitoring_operated"]]
	_unmet(facts)
	msg := sprintf("COBIT MEA01: Performance and conformance monitoring of I&T not operated%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["mea", "internal_control_assessed"]]
	_unmet(facts)
	msg := sprintf("COBIT MEA02: System of internal control not monitored and assessed%s", [_evidence(facts)])
}

violations contains msg if {
	facts := [["mea", "external_compliance_assessed"]]
	_unmet(facts)
	msg := sprintf("COBIT MEA03: Compliance with external requirements not evaluated (regulatory watch, mapping, attestation)%s", [_evidence(facts)])
}

# ── Compliance Report ────────────────────────────────────────────────────────

# Defaults — without these, an undefined input field makes the
# entire compliance_report object undefined (Rego v1 behavior).
default assessment_date := "unknown"

assessment_date := input.assessment_date

default entity_name := "unknown"

entity_name := input.entity_name

compliance_report := {
	"framework": "COBIT 2019 Governance Attestation",
	"standard": "COBIT 2019 (ISACA)",
	"entity_name": entity_name,
	"assessed_at": assessment_date,
	"compliant": compliant,
	"total_controls": 18,
	"violations": violations,
	"violation_count": count(violations),
	"failed_controls": min([18, count(violations)]),
	"scope_note": "Attestation of governance-system existence at objective-cluster granularity. COBIT capability-level maturity assessment is not machine-assessable and is not claimed here. Technical substance behind APO13/DSS05 is assessed by the ISO 27001, NIST CSF, and CIS modules.",
}
