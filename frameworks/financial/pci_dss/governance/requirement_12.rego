# PCI DSS v4.0 Requirement 12 - Support Information Security with Organizational
# Policies and Programs

package pci_dss.governance.requirement_12

import rego.v1

# =================================================================
# 12.1 - Comprehensive information security policy established, published, maintained
# =================================================================

information_security_policy if {
	input.pci.security_policy.documented == true
	input.pci.security_policy.approved_by_management == true
	input.pci.security_policy.published == true
	input.pci.security_policy.communicated_to_all_users == true
	input.pci.security_policy.reviewed_annually == true
	input.pci.security_policy.updated_when_environment_changes == true
}

# Information security roles and responsibilities defined
security_roles_defined if {
	input.pci.security_roles.ciso_or_equivalent.assigned == true
	input.pci.security_roles.responsibilities.documented == true
	input.pci.security_roles.accountability.established == true
	input.pci.security_roles.executive_management.accountability == true
}

# =================================================================
# 12.2 - Acceptable use policies established for all end users
# =================================================================

acceptable_use_policy if {
	input.pci.aup.documented == true
	input.pci.aup.approved == true
	input.pci.aup.explicit_approval_required == true
	input.pci.aup.updated_annually == true
	input.pci.aup.covers.technologies == true
	input.pci.aup.covers.cardholder_data == true
	input.pci.aup.covers.internet_usage == true
	input.pci.aup.covers.removable_media == true
}

# =================================================================
# 12.3 - Risks to the cardholder data environment managed
# =================================================================

risk_management_program if {
	input.pci.risk_management.annual_risk_assessment.performed == true
	input.pci.risk_management.methodology.documented == true
	input.pci.risk_management.risk_register.maintained == true
	input.pci.risk_management.treatment_plans.documented == true
	input.pci.risk_management.management_review.conducted == true
	input.pci.risk_management.threats_vulnerabilities.considered == true
	input.pci.risk_management.residual_risk.accepted_by_management == true
}

# Targeted risk analysis for technology usage
targeted_risk_analysis if {
	input.pci.targeted_risk_analysis.performed == true
	input.pci.targeted_risk_analysis.frequency.defined == true
	input.pci.targeted_risk_analysis.documents.what_is_being_protected == true
	input.pci.targeted_risk_analysis.documents.threat_actors == true
	input.pci.targeted_risk_analysis.documents.likelihood_and_impact == true
}

# Hardware and software technologies reviewed annually
technology_review if {
	input.pci.technology_review.hardware.annual == true
	input.pci.technology_review.software.annual == true
	input.pci.technology_review.end_of_life.identified == true
	input.pci.technology_review.end_of_life.plan.documented == true
}

# =================================================================
# 12.4 - PCI DSS compliance is managed
# =================================================================

pci_compliance_management if {
	input.pci.compliance_management.executive_responsibility.established == true
	input.pci.compliance_management.charter.defined == true
	input.pci.compliance_management.quarterly_review.performed == true
	input.pci.compliance_management.review.operational_security_controls == true
	input.pci.compliance_management.review.failures_reviewed == true
}

# Roles and responsibilities for PCI DSS activities
pci_responsibilities_assigned if {
	input.pci.responsibilities.all_activities.assigned == true
	input.pci.responsibilities.documented == true
	input.pci.responsibilities.communicated == true
}

# =================================================================
# 12.5 - PCI DSS scope is documented and validated
# =================================================================

pci_scope_documented if {
	input.pci.scope.cde.documented == true
	input.pci.scope.all_system_components.identified == true
	input.pci.scope.connected_systems.identified == true
	input.pci.scope.network_diagrams.current == true
	input.pci.scope.data_flow_diagrams.current == true
	input.pci.scope.validation.annual == true
	input.pci.scope.validation.after_significant_changes == true
}

# PAN stored, processed, or transmitted — locations identified
pan_data_locations if {
	input.pci.pan_locations.all_identified == true
	input.pci.pan_locations.storage.verified_limited == true
	input.pci.pan_locations.review.annual == true
}

# =================================================================
# 12.6 - Security awareness education implemented
# =================================================================

security_awareness_program if {
	input.pci.security_awareness.program.implemented == true
	input.pci.security_awareness.new_hires.training_upon_hire == true
	input.pci.security_awareness.frequency.at_least_annually == true
	input.pci.security_awareness.topics.security_policies == true
	input.pci.security_awareness.topics.phishing == true
	input.pci.security_awareness.topics.cardholder_data_handling == true
	input.pci.security_awareness.completion.tracked == true
	input.pci.security_awareness.acknowledgment.required == true
}

# Specific training for personnel in high-risk roles
targeted_security_training if {
	input.pci.targeted_training.high_risk_roles.identified == true
	input.pci.targeted_training.additional_training.provided == true
	input.pci.targeted_training.completion.tracked == true
}

# =================================================================
# 12.7 - Personnel screened to minimize risks of insider attacks
# =================================================================

personnel_screening if {
	input.pci.personnel_screening.background_checks.conducted == true
	input.pci.personnel_screening.before_access.to_cde == true
	input.pci.personnel_screening.local_laws.complied_with == true
}

# =================================================================
# 12.8 - Risk posed by third parties managed
# =================================================================

third_party_risk_management if {
	input.pci.third_party.inventory.maintained == true
	input.pci.third_party.inventory.pci_impact.documented == true
	input.pci.third_party.due_diligence.conducted == true
	input.pci.third_party.agreements.include_pci_compliance == true
	input.pci.third_party.agreements.security_requirements == true
	input.pci.third_party.monitoring.program == true
	input.pci.third_party.compliance_status.tracked == true
}

# Third parties acknowledge their responsibility for PCI DSS security
third_party_acknowledgment if {
	input.pci.third_party.acknowledgment.pci_compliance_responsibility == true
	input.pci.third_party.acknowledgment.documented == true
}

# =================================================================
# 12.9 - Third-party service providers acknowledge responsibility
# =================================================================

tpsp_accountability if {
	input.pci.tpsp.list.maintained == true
	input.pci.tpsp.compliance.pci_dss_compliant == true
	input.pci.tpsp.responsibilities.documented == true
	input.pci.tpsp.aoc.obtained == true
}

# =================================================================
# 12.10 - Suspected and confirmed security incidents responded to immediately
# =================================================================

incident_response_plan if {
	input.pci.incident_response.plan.documented == true
	input.pci.incident_response.plan.approved == true
	input.pci.incident_response.plan.tested.annual == true
	input.pci.incident_response.roles.designated == true
	input.pci.incident_response.training.conducted == true
	input.pci.incident_response.monitoring.for_alerts == true
	input.pci.incident_response.alerts.addressed_timely == true
}

# Incident response procedures cover all required scenarios
incident_response_scope if {
	input.pci.incident_response.scenarios.chd_compromise == true
	input.pci.incident_response.scenarios.system_compromise == true
	input.pci.incident_response.scenarios.phishing_attack == true
	input.pci.incident_response.scenarios.insider_threat == true
	input.pci.incident_response.scenarios.ransomware == true
}

# Communication plan
incident_response_communication if {
	input.pci.incident_response.communication.card_brands.notification_procedures == true
	input.pci.incident_response.communication.acquirer.notification_procedures == true
	input.pci.incident_response.communication.legal.counsel_included == true
	input.pci.incident_response.communication.pr.procedures_defined == true
}

# Forensic readiness
forensic_readiness if {
	input.pci.forensic_readiness.evidence_preservation.procedures == true
	input.pci.forensic_readiness.forensic_firm.on_retainer == true
	input.pci.forensic_readiness.chain_of_custody.procedures == true
}

# =================================================================
# Scoring
# =================================================================

pci_requirement_12_compliant if {
	information_security_policy
	security_roles_defined
	acceptable_use_policy
	risk_management_program
	pci_compliance_management
	pci_scope_documented
	security_awareness_program
	personnel_screening
	third_party_risk_management
	tpsp_accountability
	incident_response_plan
}

pci_requirement_12_score := score if {
	controls := [
		information_security_policy,
		security_roles_defined,
		acceptable_use_policy,
		risk_management_program,
		targeted_risk_analysis,
		technology_review,
		pci_compliance_management,
		pci_responsibilities_assigned,
		pci_scope_documented,
		pan_data_locations,
		security_awareness_program,
		targeted_security_training,
		personnel_screening,
		third_party_risk_management,
		third_party_acknowledgment,
		tpsp_accountability,
		incident_response_plan,
		incident_response_scope,
		incident_response_communication,
		forensic_readiness,
	]
	passed := count([c | some c in controls; c == true])
	total := count(controls)
	score := (passed / total) * 100
}

pci_requirement_12_findings := {
	"requirement_12_1": {
		"information_security_policy": information_security_policy,
		"security_roles_defined": security_roles_defined,
	},
	"requirement_12_2": {
		"acceptable_use_policy": acceptable_use_policy,
	},
	"requirement_12_3": {
		"risk_management": risk_management_program,
		"targeted_risk_analysis": targeted_risk_analysis,
		"technology_review": technology_review,
	},
	"requirement_12_4": {
		"pci_compliance_management": pci_compliance_management,
		"responsibilities_assigned": pci_responsibilities_assigned,
	},
	"requirement_12_5": {
		"scope_documented": pci_scope_documented,
		"pan_locations": pan_data_locations,
	},
	"requirement_12_6": {
		"awareness_program": security_awareness_program,
		"targeted_training": targeted_security_training,
	},
	"requirement_12_7": {
		"personnel_screening": personnel_screening,
	},
	"requirement_12_8_9": {
		"third_party_risk": third_party_risk_management,
		"third_party_acknowledgment": third_party_acknowledgment,
		"tpsp_accountability": tpsp_accountability,
	},
	"requirement_12_10": {
		"incident_response_plan": incident_response_plan,
		"incident_scope": incident_response_scope,
		"communication_plan": incident_response_communication,
		"forensic_readiness": forensic_readiness,
	},
	"overall_score": pci_requirement_12_score,
	"overall_compliant": pci_requirement_12_compliant,
}
