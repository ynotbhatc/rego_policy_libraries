package nist.csf.govern

import rego.v1

# NIST Cybersecurity Framework 2.0 - GOVERN Function
# Organizational cybersecurity risk management strategy, expectations, and policy

# GV.OC-01: Establish organizational cybersecurity strategy
organizational_strategy_established if {
    input.governance.cybersecurity_strategy.documented == true
    input.governance.cybersecurity_strategy.approved_by_leadership == true
    input.governance.cybersecurity_strategy.regularly_reviewed == true
}

# GV.OC-02: Establish cybersecurity governance and oversight
cybersecurity_governance_established if {
    input.governance.oversight_structure.exists == true
    input.governance.oversight_structure.defined_roles == true
    input.governance.oversight_structure.clear_accountability == true
}

# GV.OC-03: Establish organizational cybersecurity policy
cybersecurity_policy_established if {
    input.governance.policies.cybersecurity_policy.exists == true
    input.governance.policies.cybersecurity_policy.current == true
    input.governance.policies.cybersecurity_policy.communicated == true
}

# GV.OC-04: Establish cybersecurity roles and responsibilities
roles_responsibilities_established if {
    input.governance.roles_responsibilities.documented == true
    input.governance.roles_responsibilities.assigned == true
    input.governance.roles_responsibilities.understood == true
}

# GV.OC-05: Establish cybersecurity supply chain risk management
supply_chain_risk_management if {
    input.governance.supply_chain.risk_management_program == true
    input.governance.supply_chain.vendor_assessments == true
    input.governance.supply_chain.contractual_requirements == true
}

# GV.RM-01: Establish and maintain a comprehensive risk management strategy
risk_management_strategy if {
    input.governance.risk_management.strategy_documented == true
    input.governance.risk_management.risk_tolerance_defined == true
    input.governance.risk_management.risk_appetite_communicated == true
}

# GV.RM-02: Analyze, prioritize, and respond to risk
risk_analysis_prioritization if {
    input.governance.risk_management.regular_risk_assessments == true
    input.governance.risk_management.risk_prioritization_process == true
    input.governance.risk_management.risk_response_plans == true
}

# GV.RM-03: Risk mitigation actions are prioritized
risk_mitigation_prioritized if {
    input.governance.risk_management.mitigation_prioritization == true
    input.governance.risk_management.resource_allocation_aligned == true
    input.governance.risk_management.timeline_established == true
}

# GV.RM-04: Strategic direction informs risk management decisions
strategic_direction_informs_risk if {
    input.governance.strategic_alignment.risk_decisions_aligned == true
    input.governance.strategic_alignment.business_objectives_considered == true
    input.governance.strategic_alignment.stakeholder_input_included == true
}

# GV.RM-05: Risk management activities are coordinated across the organization
risk_coordination if {
    input.governance.coordination.cross_functional_coordination == true
    input.governance.coordination.information_sharing == true
    input.governance.coordination.collaborative_decision_making == true
}

# GV.RM-06: A standardized method for calculating and monitoring risk
standardized_risk_calculation if {
    input.governance.risk_calculation.standardized_methodology == true
    input.governance.risk_calculation.consistent_metrics == true
    input.governance.risk_calculation.regular_monitoring == true
}

# GV.RM-07: Strategic decisions are informed by risk management
strategic_decisions_risk_informed if {
    input.governance.strategic_decisions.risk_considerations_included == true
    input.governance.strategic_decisions.risk_appetite_considered == true
    input.governance.strategic_decisions.documented_rationale == true
}

# GV.SC-01: Establish and maintain cybersecurity supply chain risk management policy
supply_chain_policy if {
    input.governance.supply_chain.policy_established == true
    input.governance.supply_chain.policy_comprehensive == true
    input.governance.supply_chain.policy_regularly_updated == true
}

# GV.SC-02: Establish and maintain supplier cybersecurity requirements
supplier_requirements if {
    input.governance.supply_chain.supplier_requirements_defined == true
    input.governance.supply_chain.security_criteria_established == true
    input.governance.supply_chain.performance_standards_set == true
}

# GV.SC-03: Cybersecurity requirements are integrated into supplier relationship management
supplier_relationship_integration if {
    input.governance.supply_chain.requirements_in_contracts == true
    input.governance.supply_chain.ongoing_assessment_processes == true
    input.governance.supply_chain.relationship_monitoring == true
}

# GV.SC-04: Suppliers are assessed prior to establishing relationships
supplier_pre_assessment if {
    input.governance.supply_chain.pre_contract_assessments == true
    input.governance.supply_chain.due_diligence_processes == true
    input.governance.supply_chain.risk_evaluation_completed == true
}

# GV.SC-05: Suppliers are assessed during relationships
supplier_ongoing_assessment if {
    input.governance.supply_chain.continuous_monitoring == true
    input.governance.supply_chain.periodic_reviews == true
    input.governance.supply_chain.performance_tracking == true
}

# GV.SC-06: Cybersecurity supply chain risk information is shared
supply_chain_information_sharing if {
    input.governance.supply_chain.threat_intelligence_sharing == true
    input.governance.supply_chain.incident_communication == true
    input.governance.supply_chain.best_practices_sharing == true
}

# GV.PO-01: Establish and maintain cybersecurity policy
cybersecurity_policy_maintenance if {
    input.governance.policy_management.policies_current == true
    input.governance.policy_management.regular_reviews == true
    input.governance.policy_management.stakeholder_involvement == true
}

# GV.PO-02: Establish and maintain procedures to implement cybersecurity policy
cybersecurity_procedures if {
    input.governance.procedures.implementation_procedures == true
    input.governance.procedures.detailed_guidance == true
    input.governance.procedures.regularly_updated == true
}

# Aggregate NIST CSF Govern function compliance
nist_csf_govern_compliant if {
    organizational_strategy_established
    cybersecurity_governance_established
    cybersecurity_policy_established
    roles_responsibilities_established
    supply_chain_risk_management
    risk_management_strategy
    risk_analysis_prioritization
    risk_mitigation_prioritized
    strategic_direction_informs_risk
    risk_coordination
    standardized_risk_calculation
    strategic_decisions_risk_informed
    supply_chain_policy
    supplier_requirements
    supplier_relationship_integration
    supplier_pre_assessment
    supplier_ongoing_assessment
    supply_chain_information_sharing
    cybersecurity_policy_maintenance
    cybersecurity_procedures
}

# Detailed NIST CSF Govern compliance report
nist_csf_govern_compliance := {
    "organizational_strategy_established": organizational_strategy_established,
    "cybersecurity_governance_established": cybersecurity_governance_established,
    "cybersecurity_policy_established": cybersecurity_policy_established,
    "roles_responsibilities_established": roles_responsibilities_established,
    "supply_chain_risk_management": supply_chain_risk_management,
    "risk_management_strategy": risk_management_strategy,
    "risk_analysis_prioritization": risk_analysis_prioritization,
    "risk_mitigation_prioritized": risk_mitigation_prioritized,
    "strategic_direction_informs_risk": strategic_direction_informs_risk,
    "risk_coordination": risk_coordination,
    "standardized_risk_calculation": standardized_risk_calculation,
    "strategic_decisions_risk_informed": strategic_decisions_risk_informed,
    "supply_chain_policy": supply_chain_policy,
    "supplier_requirements": supplier_requirements,
    "supplier_relationship_integration": supplier_relationship_integration,
    "supplier_pre_assessment": supplier_pre_assessment,
    "supplier_ongoing_assessment": supplier_ongoing_assessment,
    "supply_chain_information_sharing": supply_chain_information_sharing,
    "cybersecurity_policy_maintenance": cybersecurity_policy_maintenance,
    "cybersecurity_procedures": cybersecurity_procedures,
    "overall_compliant": nist_csf_govern_compliant
}