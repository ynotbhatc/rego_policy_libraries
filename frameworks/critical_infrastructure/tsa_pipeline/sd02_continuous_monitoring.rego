package tsa_pipeline.sd02_continuous_monitoring

import rego.v1

# =============================================================================
# TSA Security Directive Pipeline-2021-02G
# Section III.D — Continuous Monitoring and Detection
#
# Directive:  SD Pipeline-2021-02G
# Effective:  May 3, 2026 through May 2, 2027
#
# Requirements evaluated: III.D.1.a–e, III.D.2.a–d, III.D.3.a–b,
#                         III.D.4 (12 subparagraphs)
#
# III.D requires "continuous monitoring and detection policies and procedures
# that are designed to prevent, detect, and respond to cybersecurity threats and
# anomalies affecting Critical Cyber Systems."
#
# --- INPUT CONTRACT ----------------------------------------------------------
# input.continuous_monitoring: {
#   "policy_documented": boolean,
#   "capabilities": [string],   # III.D.1 — see required_capabilities below
#   "procedures":   [string],   # III.D.2 — see required_procedures below
#   "logging": {                # III.D.3
#       "continuous_collection_and_analysis": boolean,
#       "retention_days":                     number,
#       "retention_sufficient_for_investigation": boolean
#   },
#   "ics_isolation": {          # III.D.4
#       "capability_exists":     boolean,
#       "manual_controls_documented": boolean
#   }
# }
#
# NO FACT SOURCE EXISTS YET — see sd01_cybersecurity_coordinator.rego.
#
# OPA endpoint: POST <opa_ot_url>/v1/data/tsa_pipeline/sd02_continuous_monitoring
# =============================================================================

# `input` is UNDEFINED (not {}) when OPA receives an empty request body. Routing
# every lookup through this defaulted alias makes an absent fact evaluate to the
# fail-closed default instead of silently skipping the violation rule entirely.
default facts := {}

facts := input

default compliant := false

compliant if {
	count(violations) == 0
}

# ── III.D.1 — Required capabilities ──────────────────────────────────────────

required_capabilities := {
	"malicious_email_prevention": "III.D.1.a: Prevent malicious email, such as spam and phishing emails, from adversely impacting operations",
	"malicious_ip_blocking": "III.D.1.b: Prohibit ingress and egress communications with known or suspected malicious Internet Protocol addresses",
	"malicious_domain_control": "III.D.1.c: Control impact of known or suspected malicious web domains or web applications",
	"unauthorized_code_blocking": "III.D.1.d: Block and prevent unauthorized code, including macro scripts, from executing",
	"command_and_control_monitoring": "III.D.1.e: Monitor and/or block connections from known or suspected malicious command and control servers (such as Tor exit nodes and other anonymization services)",
}

# ── III.D.2 — Required procedures ────────────────────────────────────────────

required_procedures := {
	"domain_access_auditing": "III.D.2.a: Audit unauthorized access to internet domains and addresses",
	"baseline_deviation_auditing": "III.D.2.b: Document and audit any communications between the Operational Technology system and an external system that deviates from the identified baseline of communications",
	"unauthorized_code_response": "III.D.2.c: Identify and respond to execution of unauthorized code, including macro scripts",
	"soar_capability": "III.D.2.d: Implement capabilities (such as Security, Orchestration, Automation, and Response) to define, prioritize, and drive standardized incident response activities",
}

declared_capabilities := {c | some c in object.get(facts, ["continuous_monitoring", "capabilities"], [])}

declared_procedures := {p | some p in object.get(facts, ["continuous_monitoring", "procedures"], [])}

# ── III.D — Policy exists ────────────────────────────────────────────────────

violations contains msg if {
	object.get(facts, ["continuous_monitoring", "policy_documented"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.D: No continuous monitoring and detection policies and procedures designed to prevent, detect, and respond to cybersecurity threats and anomalies affecting Critical Cyber Systems"
}

violations contains msg if {
	some capability, description in required_capabilities
	not capability in declared_capabilities
	msg := sprintf("TSA SD Pipeline-2021-02G %s — capability not implemented", [description])
}

violations contains msg if {
	some procedure, description in required_procedures
	not procedure in declared_procedures
	msg := sprintf("TSA SD Pipeline-2021-02G %s — procedure not established", [description])
}

# ── III.D.3 — Logging policies ───────────────────────────────────────────────

violations contains msg if {
	object.get(facts, ["continuous_monitoring", "logging", "continuous_collection_and_analysis"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.D.3.a: Logging policies do not require continuous collection and analyzing of data for potential intrusions and anomalous behavior"
}

violations contains msg if {
	object.get(facts, ["continuous_monitoring", "logging", "retention_sufficient_for_investigation"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.D.3.b: Logging policies do not ensure data is maintained for sufficient periods to allow for effective investigation of cybersecurity incidents"
}

# ── III.D.4 — Industrial control system isolation ────────────────────────────

violations contains msg if {
	object.get(facts, ["continuous_monitoring", "ics_isolation", "capability_exists"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.D.4: No mitigation measures or manual controls to ensure industrial control systems can be isolated when a cybersecurity incident in the Information Technology system creates risk to the safety and reliability of the Operational Technology system"
}

violations contains msg if {
	object.get(facts, ["continuous_monitoring", "ics_isolation", "manual_controls_documented"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.D.4: Manual controls for isolating industrial control systems are not documented"
}

# ── Compliance report ────────────────────────────────────────────────────────

compliance_report := {
	"directive": "TSA SD Pipeline-2021-02G",
	"section": "III.D",
	"name": "Continuous Monitoring and Detection",
	"requirements_evaluated": 12,
	"capabilities_required": count(required_capabilities),
	"capabilities_implemented": count(declared_capabilities & {c | some c, _ in required_capabilities}),
	"procedures_required": count(required_procedures),
	"procedures_established": count(declared_procedures & {p | some p, _ in required_procedures}),
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
}
