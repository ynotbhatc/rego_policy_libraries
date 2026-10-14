# METADATA
# title: "NIST Cybersecurity Framework 2.0 - GOVERN Function"
# custom:
#   class: compliance
#   framework: nist_cybersecurity_framework_2_0
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 1
#     cited: 1
#     density: section
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package nist.csf.govern

import rego.v1

# NIST Cybersecurity Framework 2.0 - GOVERN Function
# Organizational cybersecurity risk management strategy, expectations, and policy
#
# Fact checks. Each violation below is labelled with the CSF 2.0 subcategory it decides in nist.csf.main
# (CPRT ids, CSF_2_0_0). The checks were written against CSF 1.1; a check keeps deciding a subcategory only when
# its id is current in CSF 2.0 and it tests that outcome, or CPRT records its 1.1 id as moved to exactly one
# 2.0 subcategory and the check is a fair reading of that text. The other checks were removed; their lineage
# is the `legacy` data table at the end.

# CSF 2.0 GV.RM-06 (fact check): A standardized method for calculating and monitoring risk
default standardized_risk_calculation := false

standardized_risk_calculation if {
	input.governance.risk_calculation.standardized_methodology == true
	input.governance.risk_calculation.consistent_metrics == true
	input.governance.risk_calculation.regular_monitoring == true
}

# Aggregate over the predicates above (the CSF 2.0 fact checks of this function only)
default nist_csf_govern_compliant := false

nist_csf_govern_compliant if {
	standardized_risk_calculation
}

# Detailed report of the predicates above (kept for consumers; current checks only)
nist_csf_govern_compliance := {
	"standardized_risk_calculation": standardized_risk_calculation,
	"overall_compliant": nist_csf_govern_compliant,
}

# ── Violation set (CSF 2.0 subcategories decided by facts; read by nist.csf.main) ──

violation contains msg if {
	not standardized_risk_calculation
	msg := "CSF GV.RM-06: Standardized risk calculation methodology missing"
}

# Lineage of the CSF 1.1-era fact checks this module no longer evaluates (removed; data only, no rule
# behind it, not a control). Keyed by the label the check carried. status "retired": the CSF 1.1 id is
# withdrawn in CSF 2.0 (csf_2_0_ids = CPRT's destinations); "unmapped": the label reused a current CSF 2.0
# id but the check tested something else or only part of it. facts_read: the input the check read. Each 2.0
# subcategory is decided in nist.csf.main on its own basis (facts or attestation).
legacy := {
	"GV.OC-01": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.OC-01"],
		"facts_read": ["input.governance.cybersecurity_strategy.documented", "input.governance.cybersecurity_strategy.approved_by_leadership", "input.governance.cybersecurity_strategy.regularly_reviewed"],
		"legacy_message": "Organizational cybersecurity strategy not documented/approved/reviewed",
		"reason": "CSF 2.0 GV.OC-01 reads \"The organizational mission is understood and informs cybersecurity risk management\"; this check tests a documented, leadership-approved, reviewed cybersecurity strategy, not the organizational mission",
	},
	"GV.OC-02": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.OC-02"],
		"facts_read": ["input.governance.oversight_structure.exists", "input.governance.oversight_structure.defined_roles", "input.governance.oversight_structure.clear_accountability"],
		"legacy_message": "Cybersecurity governance structure lacks defined roles or accountability",
		"reason": "CSF 2.0 GV.OC-02 reads \"Internal and external stakeholders are understood, and their needs and expectations regarding cybersecurity risk management are understood and considered\"; this check tests a governance oversight structure with defined roles and accountability, not stakeholder needs and expectations",
	},
	"GV.OC-03": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.OC-03"],
		"facts_read": ["input.governance.policies.cybersecurity_policy.exists", "input.governance.policies.cybersecurity_policy.current", "input.governance.policies.cybersecurity_policy.communicated"],
		"legacy_message": "Cybersecurity policy not established/current/communicated",
		"reason": "CSF 2.0 GV.OC-03 reads \"Legal, regulatory, and contractual requirements regarding cybersecurity - including privacy and civil liberties obligations - are understood and managed\"; this check tests that a cybersecurity policy exists, is current and communicated, not legal, regulatory and contractual requirements",
	},
	"GV.OC-04": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.OC-04"],
		"facts_read": ["input.governance.roles_responsibilities.documented", "input.governance.roles_responsibilities.assigned", "input.governance.roles_responsibilities.understood"],
		"legacy_message": "Cybersecurity roles/responsibilities not documented or assigned",
		"reason": "CSF 2.0 GV.OC-04 reads \"Critical objectives, capabilities, and services that external stakeholders depend on or expect from the organization are understood and communicated\"; this check tests documented and assigned cybersecurity roles, not critical objectives, capabilities and services external stakeholders depend on",
	},
	"GV.OC-05": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.OC-05"],
		"facts_read": ["input.governance.supply_chain.risk_management_program", "input.governance.supply_chain.vendor_assessments", "input.governance.supply_chain.contractual_requirements"],
		"legacy_message": "Supply chain risk management program not in place",
		"reason": "CSF 2.0 GV.OC-05 reads \"Outcomes, capabilities, and services that the organization depends on are understood and communicated\"; this check tests a supply chain risk management program, not the outcomes, capabilities and services the organization depends on",
	},
	"GV.RM-01": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.RM-01"],
		"facts_read": ["input.governance.risk_management.strategy_documented", "input.governance.risk_management.risk_tolerance_defined", "input.governance.risk_management.risk_appetite_communicated"],
		"legacy_message": "Risk management strategy not documented with tolerance/appetite",
		"reason": "CSF 2.0 GV.RM-01 reads \"Risk management objectives are established and agreed to by organizational stakeholders\"; this check tests a documented risk strategy with tolerance and appetite, not risk management objectives agreed by stakeholders",
	},
	"GV.RM-02": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.RM-02"],
		"facts_read": ["input.governance.risk_management.regular_risk_assessments", "input.governance.risk_management.risk_prioritization_process", "input.governance.risk_management.risk_response_plans"],
		"legacy_message": "Risk analysis, prioritization, and response plans missing",
		"reason": "CSF 2.0 GV.RM-02 reads \"Risk appetite and risk tolerance statements are established, communicated, and maintained\"; this check tests regular risk assessments, prioritization and response plans, not risk appetite and tolerance statements",
	},
	"GV.RM-03": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.RM-03"],
		"facts_read": ["input.governance.risk_management.mitigation_prioritization", "input.governance.risk_management.resource_allocation_aligned", "input.governance.risk_management.timeline_established"],
		"legacy_message": "Risk mitigation actions not prioritized with timelines",
		"reason": "CSF 2.0 GV.RM-03 reads \"Cybersecurity risk management activities and outcomes are included in enterprise risk management processes\"; this check tests prioritized mitigation with resources and timelines, not inclusion of cybersecurity risk in enterprise risk management",
	},
	"GV.RM-04": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.RM-04"],
		"facts_read": ["input.governance.strategic_alignment.risk_decisions_aligned", "input.governance.strategic_alignment.business_objectives_considered", "input.governance.strategic_alignment.stakeholder_input_included"],
		"legacy_message": "Strategic direction not linked to risk management decisions",
		"reason": "CSF 2.0 GV.RM-04 reads \"Strategic direction that describes appropriate risk response options is established and communicated\"; this check tests that risk decisions align with business objectives, not established and communicated strategic direction on risk response options",
	},
	"GV.RM-05": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.RM-05"],
		"facts_read": ["input.governance.coordination.cross_functional_coordination", "input.governance.coordination.information_sharing", "input.governance.coordination.collaborative_decision_making"],
		"legacy_message": "Risk management activities are coordinated across the organization",
		"reason": "CSF 2.0 GV.RM-05 reads \"Lines of communication across the organization are established for cybersecurity risks, including risks from suppliers and other third parties\"; this check tests cross-functional coordination and information sharing, not established lines of communication including supplier and third-party risks (never emitted a violation) The predicate never emitted a violation.",
	},
	"GV.RM-07": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.RM-07"],
		"facts_read": ["input.governance.strategic_decisions.risk_considerations_included", "input.governance.strategic_decisions.risk_appetite_considered", "input.governance.strategic_decisions.documented_rationale"],
		"legacy_message": "Strategic decisions are informed by risk management",
		"reason": "CSF 2.0 GV.RM-07 reads \"Strategic opportunities (i.e., positive risks) are characterized and are included in organizational cybersecurity risk discussions\"; this check tests that strategic decisions consider risk, not characterization of strategic opportunities (positive risks) (never emitted a violation) The predicate never emitted a violation.",
	},
	"GV.PO-01": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.PO-01"],
		"facts_read": ["input.governance.policy_management.policies_current", "input.governance.policy_management.regular_reviews", "input.governance.policy_management.stakeholder_involvement"],
		"legacy_message": "Cybersecurity policy maintenance process missing",
		"reason": "CSF 2.0 GV.PO-01 reads \"Policy for managing cybersecurity risks is established based on organizational context, cybersecurity strategy, and priorities and is communicated and enforced\"; this check tests that policies are current, reviewed and involve stakeholders (closer to the GV.PO-02 text), not policy established from context and strategy and enforced",
	},
	"GV.PO-02": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.PO-02"],
		"facts_read": ["input.governance.procedures.implementation_procedures", "input.governance.procedures.detailed_guidance", "input.governance.procedures.regularly_updated"],
		"legacy_message": "Procedures to implement cybersecurity policy not maintained",
		"reason": "CSF 2.0 GV.PO-02 reads \"Policy for managing cybersecurity risks is reviewed, updated, communicated, and enforced to reflect changes in requirements, threats, technology, and organizational mission\"; this check tests implementation procedures, not review and update of the policy",
	},
	"GV.SC-01": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.SC-01"],
		"facts_read": ["input.governance.supply_chain.policy_established", "input.governance.supply_chain.policy_comprehensive", "input.governance.supply_chain.policy_regularly_updated"],
		"legacy_message": "Supply chain cybersecurity policy not maintained",
		"reason": "CSF 2.0 GV.SC-01 reads \"A cybersecurity supply chain risk management program, strategy, objectives, policies, and processes are established and agreed to by organizational stakeholders\"; this check tests only the supply chain policy, not the C-SCRM program, strategy, objectives and processes or stakeholder agreement",
	},
	"GV.SC-02": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.SC-02"],
		"facts_read": ["input.governance.supply_chain.supplier_requirements_defined", "input.governance.supply_chain.security_criteria_established", "input.governance.supply_chain.performance_standards_set"],
		"legacy_message": "Establish and maintain supplier cybersecurity requirements",
		"reason": "CSF 2.0 GV.SC-02 reads \"Cybersecurity roles and responsibilities for suppliers, customers, and partners are established, communicated, and coordinated internally and externally\"; this check tests supplier requirements and performance standards, not roles and responsibilities for suppliers, customers and partners (never emitted a violation) The predicate never emitted a violation.",
	},
	"GV.SC-03": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.SC-03"],
		"facts_read": ["input.governance.supply_chain.requirements_in_contracts", "input.governance.supply_chain.ongoing_assessment_processes", "input.governance.supply_chain.relationship_monitoring"],
		"legacy_message": "Cybersecurity requirements are integrated into supplier relationship management",
		"reason": "CSF 2.0 GV.SC-03 reads \"Cybersecurity supply chain risk management is integrated into cybersecurity and enterprise risk management, risk assessment, and improvement processes\"; this check tests requirements in supplier contracts and relationship monitoring, not integration of C-SCRM into cybersecurity and enterprise risk management (never emitted a violation) The predicate never emitted a violation.",
	},
	"GV.SC-04": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.SC-04"],
		"facts_read": ["input.governance.supply_chain.pre_contract_assessments", "input.governance.supply_chain.due_diligence_processes", "input.governance.supply_chain.risk_evaluation_completed"],
		"legacy_message": "Suppliers not assessed prior to establishing relationships",
		"reason": "CSF 2.0 GV.SC-04 reads \"Suppliers are known and prioritized by criticality\"; this check tests supplier assessment before a relationship, not that suppliers are known and prioritized by criticality",
	},
	"GV.SC-05": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.SC-05"],
		"facts_read": ["input.governance.supply_chain.continuous_monitoring", "input.governance.supply_chain.periodic_reviews", "input.governance.supply_chain.performance_tracking"],
		"legacy_message": "Suppliers not continuously assessed during relationships",
		"reason": "CSF 2.0 GV.SC-05 reads \"Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts and other types of agreements with suppliers and other relevant third parties\"; this check tests ongoing supplier assessment, not requirements integrated into contracts and agreements",
	},
	"GV.SC-06": {
		"csf_1_1_id": null,
		"status": "unmapped",
		"csf_2_0_ids": ["GV.SC-06"],
		"facts_read": ["input.governance.supply_chain.threat_intelligence_sharing", "input.governance.supply_chain.incident_communication", "input.governance.supply_chain.best_practices_sharing"],
		"legacy_message": "Cybersecurity supply chain risk information is shared",
		"reason": "CSF 2.0 GV.SC-06 reads \"Planning and due diligence are performed to reduce risks before entering into formal supplier or other third-party relationships\"; this check tests supply chain information sharing, not planning and due diligence before supplier relationships (never emitted a violation) The predicate never emitted a violation.",
	},
}
