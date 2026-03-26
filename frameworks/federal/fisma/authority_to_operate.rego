package fisma.ato

import rego.v1

# Authority to Operate (ATO) Assessment Policy
# RMF Step 6: Authorize - Risk-based authorization decision for federal information systems
# Evaluates readiness for ATO based on complete authorization package and risk assessment

# Main ATO Readiness Assessment
ato_ready if {
	authorization_package_complete
	risk_assessment_acceptable
	security_controls_effective
	plan_of_actions_acceptable
	authorizing_official_prepared
	ongoing_authorization_considerations
}

# Authorization Package Completeness
authorization_package_complete if {
	system_security_plan_adequate
	security_assessment_report_adequate
	plan_of_action_milestones_adequate
	risk_assessment_report_adequate
	supporting_documentation_complete
}

system_security_plan_adequate if {
	input.ato.authorization_package.ssp.document_current == true
	input.ato.authorization_package.ssp.version_approved == true
	input.ato.authorization_package.ssp.system_categorization_documented == true
	input.ato.authorization_package.ssp.control_implementation_documented == true
	input.ato.authorization_package.ssp.system_boundary_defined == true
	input.ato.authorization_package.ssp.interconnections_documented == true
	input.ato.authorization_package.ssp.responsible_parties_identified == true
}

security_assessment_report_adequate if {
	input.ato.authorization_package.sar.independent_assessment_conducted == true
	input.ato.authorization_package.sar.assessment_procedures_followed == true
	input.ato.authorization_package.sar.all_controls_assessed == true
	input.ato.authorization_package.sar.findings_documented == true
	input.ato.authorization_package.sar.recommendations_provided == true
	input.ato.authorization_package.sar.risk_ratings_assigned == true
	input.ato.authorization_package.sar.assessment_current == true
}

plan_of_action_milestones_adequate if {
	count(input.ato.authorization_package.poam.action_items) >= 0
	every item in input.ato.authorization_package.poam.action_items {
		item.weakness_id != ""
		item.description != ""
		item.resources_required != ""
		item.completion_date != ""
		item.risk_rating in ["low", "moderate", "high", "very_high"]
		item.status in ["ongoing", "completed", "delayed", "not_started"]
	}
	input.ato.authorization_package.poam.risk_tolerance_acceptable == true
}

risk_assessment_report_adequate if {
	input.ato.authorization_package.risk_assessment.methodology_documented == true
	input.ato.authorization_package.risk_assessment.threat_sources_identified == true
	input.ato.authorization_package.risk_assessment.vulnerabilities_identified == true
	input.ato.authorization_package.risk_assessment.likelihood_determined == true
	input.ato.authorization_package.risk_assessment.impact_analyzed == true
	input.ato.authorization_package.risk_assessment.risk_determination_made == true
	input.ato.authorization_package.risk_assessment.current_assessment == true
}

supporting_documentation_complete if {
	input.ato.authorization_package.supporting_docs.contingency_plan_current == true
	input.ato.authorization_package.supporting_docs.configuration_management_plan == true
	input.ato.authorization_package.supporting_docs.incident_response_plan == true
	input.ato.authorization_package.supporting_docs.continuous_monitoring_plan == true
	input.ato.authorization_package.supporting_docs.privacy_impact_assessment == true
	input.ato.authorization_package.supporting_docs.interconnection_agreements == true
}

# Risk Assessment and Acceptability
risk_assessment_acceptable if {
	threat_assessment_comprehensive
	vulnerability_assessment_current
	risk_analysis_thorough
	residual_risk_acceptable
}

threat_assessment_comprehensive if {
	count(input.ato.risk_assessment.threats.threat_sources) > 0
	every threat in input.ato.risk_assessment.threats.threat_sources {
		threat.threat_source != ""
		threat.threat_events != ""
		threat.likelihood in ["very_low", "low", "moderate", "high", "very_high"]
		threat.threat_scenario != ""
	}
	input.ato.risk_assessment.threats.threat_intelligence_considered == true
}

vulnerability_assessment_current if {
	input.ato.risk_assessment.vulnerabilities.vulnerability_scan_current == true
	input.ato.risk_assessment.vulnerabilities.penetration_test_current == true
	input.ato.risk_assessment.vulnerabilities.configuration_review_current == true
	input.ato.risk_assessment.vulnerabilities.code_review_conducted == true
	count(input.ato.risk_assessment.vulnerabilities.identified_vulnerabilities) >= 0
}

risk_analysis_thorough if {
	input.ato.risk_assessment.analysis.threat_vulnerability_pairing == true
	input.ato.risk_assessment.analysis.likelihood_determination == true
	input.ato.risk_assessment.analysis.impact_analysis == true
	input.ato.risk_assessment.analysis.risk_calculation == true
	input.ato.risk_assessment.analysis.uncertainty_factors_considered == true
}

residual_risk_acceptable if {
	input.ato.risk_assessment.residual_risk.overall_risk_level in ["low", "moderate"]
	input.ato.risk_assessment.residual_risk.high_risks_mitigated == true
	input.ato.risk_assessment.residual_risk.risk_tolerance_within_limits == true
	input.ato.risk_assessment.residual_risk.compensating_controls_effective == true
}

# Security Controls Effectiveness
security_controls_effective if {
	control_implementation_verified
	control_testing_adequate
	control_deficiencies_addressed
	control_inheritance_validated
}

control_implementation_verified if {
	input.ato.controls.implementation.implementation_percentage >= 95
	input.ato.controls.implementation.evidence_artifacts_available == true
	input.ato.controls.implementation.configuration_verified == true
	input.ato.controls.implementation.procedures_documented == true
}

control_testing_adequate if {
	input.ato.controls.testing.examine_procedures_conducted == true
	input.ato.controls.testing.interview_procedures_conducted == true
	input.ato.controls.testing.test_procedures_conducted == true
	input.ato.controls.testing.sampling_adequate == true
	input.ato.controls.testing.independent_testing == true
}

control_deficiencies_addressed if {
	input.ato.controls.deficiencies.critical_deficiencies_resolved == true
	input.ato.controls.deficiencies.high_deficiencies_plan_approved == true
	input.ato.controls.deficiencies.moderate_deficiencies_documented == true
	input.ato.controls.deficiencies.compensating_controls_implemented == true
}

control_inheritance_validated if {
	input.ato.controls.inheritance.common_controls_authorized == true
	input.ato.controls.inheritance.inheritance_documented == true
	input.ato.controls.inheritance.provider_assessments_current == true
	input.ato.controls.inheritance.responsibility_matrix_accurate == true
}

# Plan of Action and Milestones (POA&M) Acceptability
plan_of_actions_acceptable if {
	poam_completeness_adequate
	remediation_plans_reasonable
	resource_allocation_adequate
	timeline_realistic
}

poam_completeness_adequate if {
	input.ato.poam.completeness.all_weaknesses_documented == true
	input.ato.poam.completeness.root_cause_analysis_conducted == true
	input.ato.poam.completeness.risk_ratings_accurate == true
	input.ato.poam.completeness.dependencies_identified == true
}

remediation_plans_reasonable if {
	input.ato.poam.remediation.strategies_documented == true
	input.ato.poam.remediation.alternative_approaches_considered == true
	input.ato.poam.remediation.cost_benefit_analyzed == true
	input.ato.poam.remediation.feasibility_assessed == true
}

resource_allocation_adequate if {
	input.ato.poam.resources.funding_identified == true
	input.ato.poam.resources.personnel_assigned == true
	input.ato.poam.resources.technical_resources_available == true
	input.ato.poam.resources.vendor_support_confirmed == true
}

timeline_realistic if {
	input.ato.poam.timeline.milestones_reasonable == true
	input.ato.poam.timeline.dependencies_considered == true
	input.ato.poam.timeline.contingency_planning == true
	input.ato.poam.timeline.progress_tracking_implemented == true
}

# Authorizing Official Preparedness
authorizing_official_prepared if {
	ao_role_understanding
	risk_decision_framework
	oversight_mechanisms
	accountability_measures
}

ao_role_understanding if {
	input.ato.authorizing_official.role.authority_documented == true
	input.ato.authorizing_official.role.responsibilities_understood == true
	input.ato.authorizing_official.role.accountability_accepted == true
	input.ato.authorizing_official.role.decision_criteria_established == true
}

risk_decision_framework if {
	input.ato.authorizing_official.decision_framework.risk_tolerance_defined == true
	input.ato.authorizing_official.decision_framework.decision_criteria_documented == true
	input.ato.authorizing_official.decision_framework.escalation_procedures == true
	input.ato.authorizing_official.decision_framework.review_process_established == true
}

oversight_mechanisms if {
	input.ato.authorizing_official.oversight.monitoring_requirements_defined == true
	input.ato.authorizing_official.oversight.reporting_requirements_established == true
	input.ato.authorizing_official.oversight.review_cycles_scheduled == true
	input.ato.authorizing_official.oversight.performance_metrics_defined == true
}

accountability_measures if {
	input.ato.authorizing_official.accountability.responsibility_matrix_signed == true
	input.ato.authorizing_official.accountability.delegation_documented == true
	input.ato.authorizing_official.accountability.backup_ao_identified == true
	input.ato.authorizing_official.accountability.succession_planning == true
}

# Ongoing Authorization Considerations
ongoing_authorization_considerations if {
	continuous_monitoring_ready
	reauthorization_planning
	change_management_integration
	incident_response_coordination
}

continuous_monitoring_ready if {
	input.ato.ongoing.continuous_monitoring.strategy_approved == true
	input.ato.ongoing.continuous_monitoring.tools_configured == true
	input.ato.ongoing.continuous_monitoring.procedures_documented == true
	input.ato.ongoing.continuous_monitoring.reporting_established == true
}

reauthorization_planning if {
	input.ato.ongoing.reauthorization.schedule_established == true
	input.ato.ongoing.reauthorization.triggers_defined == true
	input.ato.ongoing.reauthorization.process_documented == true
	input.ato.ongoing.reauthorization.resource_planning == true
}

change_management_integration if {
	input.ato.ongoing.change_management.change_control_process == true
	input.ato.ongoing.change_management.impact_assessment_procedures == true
	input.ato.ongoing.change_management.authorization_updates == true
	input.ato.ongoing.change_management.stakeholder_notification == true
}

incident_response_coordination if {
	input.ato.ongoing.incident_response.incident_procedures_current == true
	input.ato.ongoing.incident_response.coordination_mechanisms == true
	input.ato.ongoing.incident_response.impact_assessment_process == true
	input.ato.ongoing.incident_response.authorization_review_triggers == true
}

# ATO Decision Recommendation
ato_decision_recommendation := "AUTHORIZE" if {
	ato_ready == true
	input.ato.risk_assessment.residual_risk.overall_risk_level in ["low", "moderate"]
	input.ato.controls.deficiencies.critical_deficiencies_resolved == true
}

ato_decision_recommendation := "AUTHORIZE_WITH_CONDITIONS" if {
	authorization_package_complete == true
	security_controls_effective == true
	input.ato.risk_assessment.residual_risk.overall_risk_level == "moderate"
	count(input.ato.authorization_package.poam.action_items) > 0
	count(input.ato.authorization_package.poam.action_items) <= 10
}

ato_decision_recommendation := "INTERIM_AUTHORIZE" if {
	authorization_package_complete == true
	input.ato.risk_assessment.residual_risk.overall_risk_level == "moderate"
	input.ato.controls.deficiencies.critical_deficiencies_resolved == false
	input.ato.poam.timeline.critical_items_timeline <= 90
}

ato_decision_recommendation := "DENY" if {
	not authorization_package_complete
}

ato_decision_recommendation := "DENY" if {
	input.ato.risk_assessment.residual_risk.overall_risk_level in ["high", "very_high"]
}

# ATO Readiness Score
ato_readiness_score := score if {
	total_areas := 6
	passed_areas = count([area |
		areas = [
			authorization_package_complete,
			risk_assessment_acceptable,
			security_controls_effective,
			plan_of_actions_acceptable,
			authorizing_official_prepared,
			ongoing_authorization_considerations,
		]
		area = areas[_]
		area == true
	])
	score := (passed_areas * 100) / total_areas
}

# ATO Deficiencies
ato_deficiencies := deficiencies if {
	package_deficiencies = [deficiency |
		not authorization_package_complete
		deficiency = {
			"area": "Authorization Package",
			"severity": "critical",
			"description": "Authorization package is incomplete or inadequate",
			"remediation": "Complete SSP, SAR, POA&M, risk assessment, and supporting documentation",
		}
	]

	risk_deficiencies = [deficiency |
		not risk_assessment_acceptable
		deficiency = {
			"area": "Risk Assessment",
			"severity": "high",
			"description": "Risk assessment is inadequate or residual risk is unacceptable",
			"remediation": "Conduct comprehensive threat and vulnerability assessments, analyze risks thoroughly",
		}
	]

	control_deficiencies = [deficiency |
		not security_controls_effective
		deficiency = {
			"area": "Security Controls",
			"severity": "critical",
			"description": "Security controls are not effectively implemented or tested",
			"remediation": "Complete control implementation, conduct adequate testing, address deficiencies",
		}
	]

	poam_deficiencies = [deficiency |
		not plan_of_actions_acceptable
		deficiency = {
			"area": "Plan of Action and Milestones",
			"severity": "high",
			"description": "POA&M is incomplete or remediation plans are inadequate",
			"remediation": "Develop complete remediation plans with realistic timelines and adequate resources",
		}
	]

	ao_deficiencies = [deficiency |
		not authorizing_official_prepared
		deficiency = {
			"area": "Authorizing Official Preparedness",
			"severity": "medium",
			"description": "Authorizing Official is not adequately prepared for risk-based decision",
			"remediation": "Establish decision framework, oversight mechanisms, and accountability measures",
		}
	]

	ongoing_deficiencies = [deficiency |
		not ongoing_authorization_considerations
		deficiency = {
			"area": "Ongoing Authorization",
			"severity": "medium",
			"description": "Ongoing authorization considerations are not adequately addressed",
			"remediation": "Prepare continuous monitoring, reauthorization planning, and change management integration",
		}
	]

	deficiencies := array.concat(package_deficiencies, array.concat(risk_deficiencies, array.concat(control_deficiencies, array.concat(poam_deficiencies, array.concat(ao_deficiencies, ongoing_deficiencies)))))
}

# ATO Assessment Report
ato_assessment := {
	"ato_ready": ato_ready == true,
	"readiness_score": ato_readiness_score,
	"decision_recommendation": ato_decision_recommendation,
	"assessment_areas": [
		{
			"area": "Authorization Package",
			"ready": authorization_package_complete == true,
			"description": "Completeness of authorization package documentation",
		},
		{
			"area": "Risk Assessment",
			"ready": risk_assessment_acceptable == true,
			"description": "Adequacy of risk assessment and residual risk acceptability",
		},
		{
			"area": "Security Controls",
			"ready": security_controls_effective == true,
			"description": "Effectiveness of security control implementation and testing",
		},
		{
			"area": "Plan of Action and Milestones",
			"ready": plan_of_actions_acceptable == true,
			"description": "Adequacy of remediation plans and timelines",
		},
		{
			"area": "Authorizing Official Preparedness",
			"ready": authorizing_official_prepared == true,
			"description": "Readiness of Authorizing Official for risk-based decision",
		},
		{
			"area": "Ongoing Authorization",
			"ready": ongoing_authorization_considerations == true,
			"description": "Preparedness for ongoing authorization and monitoring",
		},
	],
	"total_deficiencies": count(ato_deficiencies),
	"deficiencies": ato_deficiencies,
}

# ATO Metadata
ato_metadata := {
	"framework": "NIST Risk Management Framework (RMF)",
	"rmf_step": "RMF-R (Authorize)",
	"purpose": "Authority to Operate readiness assessment",
	"authority": "Authorizing Official risk-based decision",
	"scope": "Federal information systems subject to FISMA requirements",
	"decision_types": ["Authorize", "Authorize with Conditions", "Interim Authorize", "Deny"],
	"last_updated": "2025-01-06",
}