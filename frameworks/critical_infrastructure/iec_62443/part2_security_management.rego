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
    not input.security_management.csms_documented
    msg := "IEC 62443-2-1 (CSMS): No documented Cyber Security Management System. A CSMS addressing people, process, and technology controls for the IACS is required."
}

violations contains msg if {
    not input.security_management.policy_approved
    msg := "IEC 62443-2-1 (CSMS): IACS cybersecurity policy has not been approved by senior management. Management authorization and ownership of the security policy is required."
}

violations contains msg if {
    input.security_management.policy_approved
    input.security_management.policy_review_cycle_months > 12
    msg := sprintf(
        "IEC 62443-2-1 (CSMS): IACS security policy is reviewed every %v months. Policy must be reviewed at least annually and after any significant incident or organizational change.",
        [input.security_management.policy_review_cycle_months]
    )
}

violations contains msg if {
    not input.security_management.roles_responsibilities_defined
    msg := "IEC 62443-2-1 (CSMS): Security roles and responsibilities are not defined. Ownership of each security control, including an IACS Security Manager role, must be assigned."
}

# ---------------------------------------------------------------------------
# Risk Management
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.security_management.risk_management_process
    msg := "IEC 62443-2-1 (CSMS): No IACS risk management process. A formal process for identifying, assessing, and treating cybersecurity risks to the IACS is required."
}

violations contains msg if {
    not input.risk_assessment.conducted
    msg := "IEC 62443-2-1 (CSMS): No IACS cybersecurity risk assessment has been conducted. A risk assessment is the foundation for all security decisions."
}

violations contains msg if {
    input.risk_assessment.conducted
    input.risk_assessment.review_frequency_months > 24
    msg := sprintf(
        "IEC 62443-2-1 (CSMS): IACS risk assessment is reviewed every %v months. Risk assessments must be reviewed at least every 24 months or after significant system changes.",
        [input.risk_assessment.review_frequency_months]
    )
}

violations contains msg if {
    not input.risk_assessment.asset_inventory_complete
    msg := "IEC 62443-2-1 (CSMS): IACS asset inventory is incomplete. A complete asset inventory is a prerequisite for risk assessment and security program effectiveness."
}

violations contains msg if {
    not input.risk_assessment.threat_modeling_performed
    msg := "IEC 62443-2-1 (CSMS): No threat modeling performed for IACS. Threat modeling (identifying realistic threat actors and attack vectors) must inform risk treatment decisions."
}

violations contains msg if {
    not input.risk_assessment.consequence_analysis_performed
    msg := "IEC 62443-2-1 (CSMS): No consequence analysis performed. Impact analysis of cyber incidents on safety, operations, environment, and business continuity is required."
}

# ---------------------------------------------------------------------------
# Security Awareness and Training
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.security_management.security_awareness_training
    msg := "IEC 62443-2-1 (CSMS): No security awareness training for IACS personnel. All employees with IACS access must receive role-appropriate cybersecurity training."
}

violations contains msg if {
    input.security_management.security_awareness_training
    input.security_management.training_frequency_months > 12
    msg := sprintf(
        "IEC 62443-2-1 (CSMS): IACS security training is conducted every %v months. Training must be conducted at least annually.",
        [input.security_management.training_frequency_months]
    )
}

# ---------------------------------------------------------------------------
# Incident Response
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.security_management.incident_response_capability
    msg := "IEC 62443-2-1 (CSMS): No IACS incident response capability. A documented ICS-specific incident response plan with trained personnel and clear escalation paths is required."
}

# ---------------------------------------------------------------------------
# Supply Chain Security
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.security_management.supply_chain_security
    msg := "IEC 62443-2-1 (CSMS): No supply chain security program for IACS. Security requirements must extend to OT vendors, integrators, and managed service providers with IACS access."
}

violations contains msg if {
    not input.security_management.third_party_security_requirements
    msg := "IEC 62443-2-1 (CSMS): Security requirements are not imposed on third parties. All vendors and contractors with IACS access must meet defined security requirements (ref: IEC 62443-2-4)."
}

# ---------------------------------------------------------------------------
# Continuous Improvement
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.security_management.security_metrics_tracked
    msg := "IEC 62443-2-1 (CSMS): No security metrics tracked. The CSMS must define and track key performance indicators (KPIs) for measuring security effectiveness."
}

violations contains msg if {
    not input.security_management.csms_audit_conducted
    msg := "IEC 62443-2-1 (CSMS): No CSMS audit conducted. The CSMS must be periodically audited against the defined objectives and requirements."
}

violations contains msg if {
    input.security_management.csms_audit_conducted
    input.security_management.csms_audit_frequency_months > 24
    msg := sprintf(
        "IEC 62443-2-1 (CSMS): CSMS audits are conducted every %v months. Audits must be conducted at least every 24 months.",
        [input.security_management.csms_audit_frequency_months]
    )
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

compliant if { count(violations) == 0 }

compliance_report := {
    "part":       "IEC 62443-2-1",
    "title":      "Security Management System (CSMS) Requirements",
    "standard":   "IEC 62443-2-1",
    "compliant":  compliant,
    "violations": violations,
}
