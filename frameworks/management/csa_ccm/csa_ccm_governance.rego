package csa_ccm.governance

import rego.v1

default compliant := false

violations contains msg if {
    not input.csa_ccm.governance.security_framework.framework_established
    msg := "GRC-01: Information security governance framework not formally established"
}

violations contains msg if {
    not input.csa_ccm.governance.security_framework.cloud_governance_included
    msg := "GRC-01: Cloud computing governance not explicitly included in the security governance framework"
}

violations contains msg if {
    not input.csa_ccm.governance.security_framework.framework_aligned_to_standard
    msg := "GRC-01: Governance framework not aligned to a recognized standard (ISO 27001, NIST CSF, CSA CCM)"
}

violations contains msg if {
    not input.csa_ccm.governance.security_framework.framework_documented
    msg := "GRC-01: Information security governance framework not formally documented and published"
}

violations contains msg if {
    not input.csa_ccm.governance.security_framework.reviewed_annually
    msg := "GRC-01: Information security governance framework not reviewed at least annually"
}

violations contains msg if {
    not input.csa_ccm.governance.roles_responsibilities.ciso_or_equivalent_defined
    msg := "GRC-02: CISO or equivalent cloud security leadership role not formally defined"
}

violations contains msg if {
    not input.csa_ccm.governance.roles_responsibilities.cloud_security_roles_documented
    msg := "GRC-02: Roles and responsibilities for cloud security not documented and communicated"
}

violations contains msg if {
    not input.csa_ccm.governance.roles_responsibilities.accountability_assigned
    msg := "GRC-02: Accountability for cloud security outcomes not assigned to named individuals or roles"
}

violations contains msg if {
    not input.csa_ccm.governance.roles_responsibilities.raci_or_equivalent_defined
    msg := "GRC-02: RACI or equivalent responsibility matrix not defined for cloud security functions"
}

violations contains msg if {
    not input.csa_ccm.governance.risk_management.risk_program_exists
    msg := "GRC-03: Risk management program not established for cloud and information security"
}

violations contains msg if {
    not input.csa_ccm.governance.risk_management.risk_register_maintained
    msg := "GRC-03: Risk register not maintained — identified risks must be documented with likelihood and impact"
}

violations contains msg if {
    not input.csa_ccm.governance.risk_management.risk_treatment_plans_defined
    msg := "GRC-03: Risk treatment plans not defined for accepted or mitigated risks"
}

violations contains msg if {
    not input.csa_ccm.governance.risk_management.risk_review_cadence
    msg := "GRC-03: Risk reviews not conducted at defined intervals — risk posture must be regularly reassessed"
}

violations contains msg if {
    not input.csa_ccm.governance.risk_management.risk_aligned_to_business_objectives
    msg := "GRC-03: Risk management program not aligned to organizational business objectives and risk appetite"
}

violations contains msg if {
    not input.csa_ccm.governance.compliance_obligations.obligations_inventoried
    msg := "GRC-04: Compliance obligations not inventoried — all applicable legal, regulatory, and contractual requirements must be catalogued"
}

violations contains msg if {
    not input.csa_ccm.governance.compliance_obligations.obligations_tracked
    msg := "GRC-04: Compliance obligation status not tracked — adherence to each obligation must be monitored"
}

violations contains msg if {
    not input.csa_ccm.governance.compliance_obligations.gaps_identified_and_remediated
    msg := "GRC-04: Compliance gaps not identified and tracked to remediation"
}

violations contains msg if {
    not input.csa_ccm.governance.compliance_obligations.regulatory_change_monitoring
    msg := "GRC-04: Process not established to monitor for changes in applicable regulatory requirements"
}

violations contains msg if {
    not input.csa_ccm.governance.executive_approval.policies_executive_approved
    msg := "GRC-05: Cloud security policies not formally approved by executive leadership"
}

violations contains msg if {
    not input.csa_ccm.governance.executive_approval.cloud_strategy_approved
    msg := "GRC-05: Cloud strategy not formally approved by executive leadership"
}

violations contains msg if {
    not input.csa_ccm.governance.executive_approval.security_budget_allocated
    msg := "GRC-05: Security budget not allocated by executive leadership as part of approved strategy"
}

violations contains msg if {
    not input.csa_ccm.governance.executive_approval.board_oversight_exists
    msg := "GRC-05: Board-level oversight of cloud security and risk management not established"
}

violations contains msg if {
    not input.csa_ccm.governance.metrics.metrics_defined
    msg := "GRC-06: Security metrics and KPIs not defined for the cloud security program"
}

violations contains msg if {
    not input.csa_ccm.governance.metrics.metrics_reported_to_leadership
    msg := "GRC-06: Security metrics not regularly reported to executive leadership and board"
}

violations contains msg if {
    not input.csa_ccm.governance.metrics.metrics_actionable
    msg := "GRC-06: Security metrics not actionable — metrics must drive decisions and program improvements"
}

violations contains msg if {
    not input.csa_ccm.governance.metrics.metrics_reviewed_regularly
    msg := "GRC-06: Security metrics and KPIs not reviewed regularly to assess relevance and effectiveness"
}

compliant if { count(violations) == 0 }

compliance_report := {
    "domain": "GRC — Governance, Risk & Compliance",
    "compliant": compliant,
    "violation_count": count(violations),
    "violations": violations,
}
