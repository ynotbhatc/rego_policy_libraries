package cobit.main

import rego.v1

# COBIT 2019 — Governance and Management of Enterprise I&T (ISACA)
#
# HONEST SCOPE — read before quoting this to anyone: COBIT is a
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

# ── EDM — Evaluate, Direct and Monitor (governance) ──────────────────────────

violations contains msg if {
	not input.edm.governance_framework_established
	msg := "COBIT EDM01: Governance framework for enterprise I&T not established and maintained by the governing body"
}

violations contains msg if {
	not input.edm.benefits_delivery_overseen
	msg := "COBIT EDM02: Benefits delivery from I&T investments not evaluated, directed, and monitored"
}

violations contains msg if {
	not input.edm.risk_optimization_overseen
	msg := "COBIT EDM03: I&T risk appetite not defined and risk optimization not overseen by the governing body"
}

violations contains msg if {
	not input.edm.resource_optimization_overseen
	msg := "COBIT EDM04: I&T resource optimization (people, process, technology) not overseen"
}

violations contains msg if {
	not input.edm.stakeholder_engagement
	msg := "COBIT EDM05: Stakeholder engagement and transparent I&T reporting not directed and monitored"
}

# ── APO — Align, Plan and Organize ───────────────────────────────────────────

violations contains msg if {
	not input.apo.it_strategy_documented
	msg := "COBIT APO02: I&T strategy aligned to enterprise goals not documented and maintained"
}

violations contains msg if {
	not input.apo.enterprise_architecture_managed
	msg := "COBIT APO03: Enterprise architecture not managed"
}

violations contains msg if {
	not input.apo.risk_management_operated
	msg := "COBIT APO12: I&T risk management process not operated (identify, assess, respond, monitor)"
}

violations contains msg if {
	not input.apo.security_management_defined
	msg := "COBIT APO13: Information security management system not defined and operated (see ISO 27001 module for ISMS technical depth)"
}

violations contains msg if {
	not input.apo.vendor_management_operated
	msg := "COBIT APO10: Vendor/third-party service management not operated"
}

# ── BAI — Build, Acquire and Implement ───────────────────────────────────────

violations contains msg if {
	not input.bai.change_management_operated
	msg := "COBIT BAI06: I&T change management process not operated"
}

violations contains msg if {
	not input.bai.configuration_management_operated
	msg := "COBIT BAI10: Configuration management (asset/CI baseline and tracking) not operated"
}

# ── DSS — Deliver, Service and Support ───────────────────────────────────────

violations contains msg if {
	not input.dss.operations_managed
	msg := "COBIT DSS01: I&T operations management not performed to defined procedures"
}

violations contains msg if {
	not input.dss.incident_management_operated
	msg := "COBIT DSS02: Service request and incident management process not operated"
}

violations contains msg if {
	not input.dss.security_services_delivered
	msg := "COBIT DSS05: Security services not delivered and monitored (see NIST CSF / CIS modules for the technical assessment behind this objective)"
}

# ── MEA — Monitor, Evaluate and Assess ───────────────────────────────────────

violations contains msg if {
	not input.mea.performance_monitoring_operated
	msg := "COBIT MEA01: Performance and conformance monitoring of I&T not operated"
}

violations contains msg if {
	not input.mea.internal_control_assessed
	msg := "COBIT MEA02: System of internal control not monitored and assessed"
}

violations contains msg if {
	not input.mea.external_compliance_assessed
	msg := "COBIT MEA03: Compliance with external requirements not evaluated (regulatory watch, mapping, attestation)"
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
	"scope_note": "Attestation of governance-system existence at objective-cluster granularity. COBIT capability-level maturity assessment is not machine-assessable and is not claimed here. Technical substance behind APO13/DSS05 is assessed by the ISO 27001, NIST CSF, and CIS modules.",
}
