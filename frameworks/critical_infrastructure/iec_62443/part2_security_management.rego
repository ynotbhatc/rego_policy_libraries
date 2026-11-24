# METADATA
# title: "IEC 62443-2-1 — Security Management System (CSMS)"
# custom:
#   class: ot
#   framework: iec_62443
#   source: iec
#   domains: [ot, industrial]
#   coverage:
#     checks: 22
#     cited: 1
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package iec_62443.part2_1

import rego.v1

# =============================================================================
# IEC 62443-2-1 — Security Management System (CSMS)
#
# Purpose: Define requirements for establishing, implementing, operating,
# monitoring, reviewing, maintaining, and improving an IACS Cyber Security
# Management System (CSMS). Analogous to ISO 27001 but specific to OT/ICS.
#
# Key Requirement Areas:
#   - Security policy and organization
#   - Risk and asset management
#   - Security implementation
#   - Security monitoring and improvement
#   - Business continuity and crisis management
#
# Input shape:
#   input.security_management
#     .csms_documented                         - bool
#     .policy_approved                         - bool
#     .policy_review_cycle_months              - int
#     .roles_responsibilities_defined          - bool
#     .security_awareness_training             - bool
#     .training_frequency_months               - int
#     .incident_response_capability            - bool
#     .supply_chain_security                   - bool
#     .risk_management_process                 - bool
#     .security_testing_schedule_documented    - bool
#     .recovery_plan_tested                    - bool
#     .configuration_change_management         - bool
#     .functionality_review_schedule           - bool
#     .inventory_auto_discovery                - bool
#     .third_party_security_requirements       - bool
#     .security_metrics_tracked                - bool
#     .csms_audit_conducted                    - bool
#     .csms_audit_frequency_months             - int
# =============================================================================

default compliant := false

# ---------------------------------------------------------------------------
# Security Policy and Organization
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.security_management.csms_documented == true
	finding := "IEC 62443-2-1 (CSMS): No documented Cyber Security Management System. A CSMS addressing people, process, and technology controls for the IACS is required."
	msg := concat("", [finding, _ev_input("security_management.csms_documented")])
}

violations contains msg if {
	not input.security_management.policy_approved == true
	finding := "IEC 62443-2-1 (CSMS): IACS cybersecurity policy has not been approved by senior management. Management authorization and ownership of the security policy is required."
	msg := concat("", [finding, _ev_input("security_management.policy_approved")])
}

violations contains msg if {
	input.security_management.policy_approved == true
	is_number(input.security_management.policy_review_cycle_months)
	input.security_management.policy_review_cycle_months > 12
	msg := sprintf(
		"IEC 62443-2-1 (CSMS): IACS security policy is reviewed every %v months. Policy must be reviewed at least annually and after any significant incident or organizational change.",
		[input.security_management.policy_review_cycle_months],
	)
}

violations contains "IEC 62443-2-1 (CSMS): evidence missing - input.security_management.policy_review_cycle_months is not a number" if {
	input.security_management.policy_approved == true
	not is_number(object.get(input, ["security_management", "policy_review_cycle_months"], null))
}

violations contains msg if {
	not input.security_management.roles_responsibilities_defined == true
	finding := "IEC 62443-2-1 (CSMS): Security roles and responsibilities are not defined. Ownership of each security control, including an IACS Security Manager role, must be assigned."
	msg := concat("", [finding, _ev_input("security_management.roles_responsibilities_defined")])
}

# ---------------------------------------------------------------------------
# Risk Management
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.security_management.risk_management_process == true
	finding := "IEC 62443-2-1 (CSMS): No IACS risk management process. A formal process for identifying, assessing, and treating cybersecurity risks to the IACS is required."
	msg := concat("", [finding, _ev_input("security_management.risk_management_process")])
}

violations contains msg if {
	not input.risk_assessment.conducted == true
	finding := "IEC 62443-2-1 (CSMS): No IACS cybersecurity risk assessment has been conducted. A risk assessment is the foundation for all security decisions."
	msg := concat("", [finding, _ev_input("risk_assessment.conducted")])
}

violations contains msg if {
	input.risk_assessment.conducted == true
	is_number(input.risk_assessment.review_frequency_months)
	input.risk_assessment.review_frequency_months > 24
	msg := sprintf(
		"IEC 62443-2-1 (CSMS): IACS risk assessment is reviewed every %v months. Risk assessments must be reviewed at least every 24 months or after significant system changes.",
		[input.risk_assessment.review_frequency_months],
	)
}

violations contains "IEC 62443-2-1 (CSMS): evidence missing - input.risk_assessment.review_frequency_months is not a number" if {
	input.risk_assessment.conducted == true
	not is_number(object.get(input, ["risk_assessment", "review_frequency_months"], null))
}

violations contains msg if {
	not input.risk_assessment.asset_inventory_complete == true
	finding := "IEC 62443-2-1 (CSMS): IACS asset inventory is incomplete. A complete asset inventory is a prerequisite for risk assessment and security program effectiveness."
	msg := concat("", [finding, _ev_input("risk_assessment.asset_inventory_complete")])
}

violations contains msg if {
	not input.risk_assessment.threat_modeling_performed == true
	finding := "IEC 62443-2-1 (CSMS): No threat modeling performed for IACS. Threat modeling (identifying realistic threat actors and attack vectors) must inform risk treatment decisions."
	msg := concat("", [finding, _ev_input("risk_assessment.threat_modeling_performed")])
}

violations contains msg if {
	not input.risk_assessment.consequence_analysis_performed == true
	finding := "IEC 62443-2-1 (CSMS): No consequence analysis performed. Impact analysis of cyber incidents on safety, operations, environment, and business continuity is required."
	msg := concat("", [finding, _ev_input("risk_assessment.consequence_analysis_performed")])
}

# ---------------------------------------------------------------------------
# Security Awareness and Training
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.security_management.security_awareness_training == true
	finding := "IEC 62443-2-1 (CSMS): No security awareness training for IACS personnel. All employees with IACS access must receive role-appropriate cybersecurity training."
	msg := concat("", [finding, _ev_input("security_management.security_awareness_training")])
}

violations contains msg if {
	input.security_management.security_awareness_training == true
	is_number(input.security_management.training_frequency_months)
	input.security_management.training_frequency_months > 12
	msg := sprintf(
		"IEC 62443-2-1 (CSMS): IACS security training is conducted every %v months. Training must be conducted at least annually.",
		[input.security_management.training_frequency_months],
	)
}

violations contains "IEC 62443-2-1 (CSMS): evidence missing - input.security_management.training_frequency_months is not a number" if {
	input.security_management.security_awareness_training == true
	not is_number(object.get(input, ["security_management", "training_frequency_months"], null))
}

# ---------------------------------------------------------------------------
# Incident Response
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.security_management.incident_response_capability == true
	finding := "IEC 62443-2-1 (CSMS): No IACS incident response capability. A documented ICS-specific incident response plan with trained personnel and clear escalation paths is required."
	msg := concat("", [finding, _ev_input("security_management.incident_response_capability")])
}

# ---------------------------------------------------------------------------
# Supply Chain Security
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.security_management.supply_chain_security == true
	finding := "IEC 62443-2-1 (CSMS): No supply chain security program for IACS. Security requirements must extend to OT vendors, integrators, and managed service providers with IACS access."
	msg := concat("", [finding, _ev_input("security_management.supply_chain_security")])
}

violations contains msg if {
	not input.security_management.third_party_security_requirements == true
	finding := "IEC 62443-2-1 (CSMS): Security requirements are not imposed on third parties. All vendors and contractors with IACS access must meet defined security requirements (ref: IEC 62443-2-4)."
	msg := concat("", [finding, _ev_input("security_management.third_party_security_requirements")])
}

# ---------------------------------------------------------------------------
# Continuous Improvement
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.security_management.security_metrics_tracked == true
	finding := "IEC 62443-2-1 (CSMS): No security metrics tracked. The CSMS must define and track key performance indicators (KPIs) for measuring security effectiveness."
	msg := concat("", [finding, _ev_input("security_management.security_metrics_tracked")])
}

violations contains msg if {
	not input.security_management.csms_audit_conducted == true
	finding := "IEC 62443-2-1 (CSMS): No CSMS audit conducted. The CSMS must be periodically audited against the defined objectives and requirements."
	msg := concat("", [finding, _ev_input("security_management.csms_audit_conducted")])
}

violations contains msg if {
	input.security_management.csms_audit_conducted == true
	is_number(input.security_management.csms_audit_frequency_months)
	input.security_management.csms_audit_frequency_months > 24
	msg := sprintf(
		"IEC 62443-2-1 (CSMS): CSMS audits are conducted every %v months. Audits must be conducted at least every 24 months.",
		[input.security_management.csms_audit_frequency_months],
	)
}

violations contains "IEC 62443-2-1 (CSMS): evidence missing - input.security_management.csms_audit_frequency_months is not a number" if {
	input.security_management.csms_audit_conducted == true
	not is_number(object.get(input, ["security_management", "csms_audit_frequency_months"], null))
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

compliant if count(violations) == 0

compliance_report := {
	"part": "IEC 62443-2-1",
	"title": "Security Management System (CSMS) Requirements",
	"standard": "IEC 62443-2-1",
	"compliant": compliant,
	"violations": violations,
}

# ---------------------------------------------------------------------------
# Evidence rule: only the boolean true passes a yes/no fact. A fact that is
# absent, null or not a boolean fails its check, and the finding names the
# evidence problem.
# ---------------------------------------------------------------------------

default _facts := {}

_facts := input

_evidence_note(value, name) := "" if {
	is_boolean(value)
} else := sprintf(" (evidence missing: %s not collected)", [name]) if {
	value == null
} else := sprintf(" (evidence invalid: %s is not a boolean, got %s)", [name, type_name(value)])

_ev_input(path) := _evidence_note(object.get(_facts, split(path, "."), null), concat(".", ["input", path]))

_ev_item(item, path) := _evidence_note(object.get(item, split(path, "."), null), path) if {
	is_object(item)
} else := sprintf(" (evidence invalid: item is not an object, got %s; %s not collected)", [type_name(item), path])
