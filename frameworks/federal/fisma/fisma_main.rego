package fisma.main

import rego.v1

# Federal Information Security Modernization Act (FISMA) 2014 Implementation
# Comprehensive FISMA compliance framework based on NIST RMF and SP 800-53
# Implements all 7 RMF steps: Prepare, Categorize, Select, Implement, Assess, Authorize, Monitor

# FISMA Core Requirements
fisma_compliant if {
	rmf_step_1_prepare_compliant
	rmf_step_2_categorize_compliant
	rmf_step_3_select_compliant
	rmf_step_4_implement_compliant
	rmf_step_5_assess_compliant
	rmf_step_6_authorize_compliant
	rmf_step_7_monitor_compliant
}

# RMF Step 1: PREPARE - Essential activities to prepare for risk management
rmf_step_1_prepare_compliant if {
	organizational_risk_strategy_established
	risk_management_roles_defined
	common_controls_identified
	impact_level_prioritization_established
	continuous_monitoring_strategy_established
}

organizational_risk_strategy_established if {
	input.fisma.prepare.risk_strategy.documented == true
	input.fisma.prepare.risk_strategy.approved == true
	input.fisma.prepare.risk_strategy.communicated == true
	input.fisma.prepare.risk_strategy.review_frequency_defined == true
}

risk_management_roles_defined if {
	input.fisma.prepare.roles.authorizing_official.assigned == true
	input.fisma.prepare.roles.senior_agency_iso.assigned == true
	input.fisma.prepare.roles.system_owner.assigned == true
	input.fisma.prepare.roles.information_system_security_officer.assigned == true
	input.fisma.prepare.roles.control_assessor.assigned == true
}

common_controls_identified if {
	count(input.fisma.prepare.common_controls) > 0
	violations := [control |
		control := input.fisma.prepare.common_controls[_]
		not control.provider_organization != ""
	]
	count(violations) == 0
	violations2 := [control |
		control := input.fisma.prepare.common_controls[_]
		not control.authorization_status in ["authorized", "not_authorized", "under_assessment"]
	]
	count(violations2) == 0
	violations3 := [control |
		control := input.fisma.prepare.common_controls[_]
		not control.inheritance_documented == true
	]
	count(violations3) == 0
}

impact_level_prioritization_established if {
	input.fisma.prepare.impact_prioritization.high_impact_systems_identified == true
	input.fisma.prepare.impact_prioritization.moderate_impact_systems_identified == true
	input.fisma.prepare.impact_prioritization.low_impact_systems_identified == true
	input.fisma.prepare.impact_prioritization.prioritization_criteria_documented == true
}

continuous_monitoring_strategy_established if {
	input.fisma.prepare.continuous_monitoring.strategy_documented == true
	input.fisma.prepare.continuous_monitoring.frequency_defined == true
	input.fisma.prepare.continuous_monitoring.automation_level_defined == true
	input.fisma.prepare.continuous_monitoring.reporting_requirements_defined == true
}

# RMF Step 2: CATEGORIZE - Categorize systems and information based on impact analysis
rmf_step_2_categorize_compliant if {
	system_security_categorization_completed
	information_types_identified
	impact_analysis_documented
	security_categorization_approved
}

system_security_categorization_completed if {
	input.fisma.categorize.system_categorization.confidentiality_impact in ["low", "moderate", "high"]
	input.fisma.categorize.system_categorization.integrity_impact in ["low", "moderate", "high"]
	input.fisma.categorize.system_categorization.availability_impact in ["low", "moderate", "high"]
	input.fisma.categorize.system_categorization.overall_impact in ["low", "moderate", "high"]
}

information_types_identified if {
	count(input.fisma.categorize.information_types) > 0
	violations := [info_type |
		info_type := input.fisma.categorize.information_types[_]
		not info_type.type_name != ""
	]
	count(violations) == 0
	violations2 := [info_type |
		info_type := input.fisma.categorize.information_types[_]
		not info_type.confidentiality_impact != ""
	]
	count(violations2) == 0
	violations3 := [info_type |
		info_type := input.fisma.categorize.information_types[_]
		not info_type.integrity_impact != ""
	]
	count(violations3) == 0
	violations4 := [info_type |
		info_type := input.fisma.categorize.information_types[_]
		not info_type.availability_impact != ""
	]
	count(violations4) == 0
	violations5 := [info_type |
		info_type := input.fisma.categorize.information_types[_]
		not info_type.rationale != ""
	]
	count(violations5) == 0
}

impact_analysis_documented if {
	input.fisma.categorize.impact_analysis.methodology_documented == true
	input.fisma.categorize.impact_analysis.assumptions_documented == true
	input.fisma.categorize.impact_analysis.risk_factors_identified == true
	input.fisma.categorize.impact_analysis.business_impact_assessed == true
}

security_categorization_approved if {
	input.fisma.categorize.approval.system_owner_approved == true
	input.fisma.categorize.approval.senior_agency_iso_reviewed == true
	input.fisma.categorize.approval.authorizing_official_endorsed == true
}

# RMF Step 3: SELECT - Select appropriate security controls
rmf_step_3_select_compliant if {
	security_control_baselines_selected
	control_tailoring_completed
	compensating_controls_identified
	security_control_allocation_documented
}

security_control_baselines_selected if {
	input.fisma.select.control_baselines.baseline_applied in ["low", "moderate", "high"]
	input.fisma.select.control_baselines.nist_sp_800_53_revision == "5"
	count(input.fisma.select.control_baselines.selected_controls) > 0
}

control_tailoring_completed if {
	count(input.fisma.select.tailoring.tailored_controls) >= 0
	violations := [tailored |
		tailored := input.fisma.select.tailoring.tailored_controls[_]
		not tailored.control_id != ""
	]
	count(violations) == 0
	violations2 := [tailored |
		tailored := input.fisma.select.tailoring.tailored_controls[_]
		not tailored.tailoring_action in ["add", "remove", "modify", "substitute"]
	]
	count(violations2) == 0
	violations3 := [tailored |
		tailored := input.fisma.select.tailoring.tailored_controls[_]
		not tailored.rationale != ""
	]
	count(violations3) == 0
	violations4 := [tailored |
		tailored := input.fisma.select.tailoring.tailored_controls[_]
		not tailored.approval_documented == true
	]
	count(violations4) == 0
}

compensating_controls_identified if {
	count(input.fisma.select.compensating_controls) >= 0
	violations := [comp |
		comp := input.fisma.select.compensating_controls[_]
		not comp.baseline_control_id != ""
	]
	count(violations) == 0
	violations2 := [comp |
		comp := input.fisma.select.compensating_controls[_]
		not comp.compensating_control_id != ""
	]
	count(violations2) == 0
	violations3 := [comp |
		comp := input.fisma.select.compensating_controls[_]
		not comp.rationale != ""
	]
	count(violations3) == 0
	violations4 := [comp |
		comp := input.fisma.select.compensating_controls[_]
		not comp.risk_acceptance_documented == true
	]
	count(violations4) == 0
}

security_control_allocation_documented if {
	input.fisma.select.allocation.system_specific_controls_identified == true
	input.fisma.select.allocation.hybrid_controls_identified == true
	input.fisma.select.allocation.common_controls_identified == true
	input.fisma.select.allocation.responsibility_matrix_documented == true
}

# RMF Step 4: IMPLEMENT - Implement security controls
rmf_step_4_implement_compliant if {
	security_controls_implemented
	implementation_documented
	system_security_plan_developed
	control_implementation_evidence_available
}

security_controls_implemented if {
	input.fisma.implement.controls.implementation_percentage >= 95
	input.fisma.implement.controls.configuration_management_applied == true
	input.fisma.implement.controls.change_control_applied == true
}

implementation_documented if {
	input.fisma.implement.documentation.control_descriptions_complete == true
	input.fisma.implement.documentation.implementation_guidance_followed == true
	input.fisma.implement.documentation.responsible_entities_identified == true
	input.fisma.implement.documentation.implementation_parameters_documented == true
}

system_security_plan_developed if {
	input.fisma.implement.ssp.document_exists == true
	input.fisma.implement.ssp.current_version == true
	input.fisma.implement.ssp.complete_control_descriptions == true
	input.fisma.implement.ssp.system_boundary_documented == true
	input.fisma.implement.ssp.interconnections_documented == true
}

control_implementation_evidence_available if {
	input.fisma.implement.evidence.artifacts_collected == true
	input.fisma.implement.evidence.testing_results_documented == true
	input.fisma.implement.evidence.configuration_baselines_established == true
	input.fisma.implement.evidence.procedures_documented == true
}

# RMF Step 5: ASSESS - Assess security control effectiveness
rmf_step_5_assess_compliant if {
	security_control_assessment_completed
	assessment_procedures_followed
	assessment_findings_documented
	remediation_plans_developed
}

security_control_assessment_completed if {
	input.fisma.assess.assessment.independent_assessor == true
	input.fisma.assess.assessment.assessment_plan_approved == true
	input.fisma.assess.assessment.all_controls_assessed == true
	input.fisma.assess.assessment.assessment_procedures_nist_800_53a == true
}

assessment_procedures_followed if {
	input.fisma.assess.procedures.examine_procedures_used == true
	input.fisma.assess.procedures.interview_procedures_used == true
	input.fisma.assess.procedures.test_procedures_used == true
	input.fisma.assess.procedures.depth_coverage_adequate == true
}

assessment_findings_documented if {
	input.fisma.assess.findings.security_assessment_report_complete == true
	input.fisma.assess.findings.deficiencies_identified == true
	input.fisma.assess.findings.recommendations_provided == true
	input.fisma.assess.findings.risk_ratings_assigned == true
}

remediation_plans_developed if {
	count(input.fisma.assess.remediation.plan_of_actions) >= 0
	violations := [poa |
		poa := input.fisma.assess.remediation.plan_of_actions[_]
		not poa.finding_id != ""
	]
	count(violations) == 0
	violations2 := [poa |
		poa := input.fisma.assess.remediation.plan_of_actions[_]
		not poa.remediation_strategy != ""
	]
	count(violations2) == 0
	violations3 := [poa |
		poa := input.fisma.assess.remediation.plan_of_actions[_]
		not poa.target_completion_date != ""
	]
	count(violations3) == 0
	violations4 := [poa |
		poa := input.fisma.assess.remediation.plan_of_actions[_]
		not poa.responsible_party != ""
	]
	count(violations4) == 0
	violations5 := [poa |
		poa := input.fisma.assess.remediation.plan_of_actions[_]
		not poa.risk_level in ["low", "moderate", "high", "very_high"]
	]
	count(violations5) == 0
}

# RMF Step 6: AUTHORIZE - Make risk-based authorization decision
rmf_step_6_authorize_compliant if {
	authorization_package_complete
	risk_assessment_conducted
	authorization_decision_documented
	terms_conditions_established
}

authorization_package_complete if {
	input.fisma.authorize["package"].system_security_plan_current == true
	input.fisma.authorize["package"].security_assessment_report_current == true
	input.fisma.authorize["package"].plan_of_action_milestones_current == true
	input.fisma.authorize["package"].risk_assessment_current == true
}

risk_assessment_conducted if {
	input.fisma.authorize.risk_assessment.methodology_documented == true
	input.fisma.authorize.risk_assessment.threat_analysis_completed == true
	input.fisma.authorize.risk_assessment.vulnerability_analysis_completed == true
	input.fisma.authorize.risk_assessment.risk_determination_documented == true
	input.fisma.authorize.risk_assessment.residual_risk_acceptable == true
}

authorization_decision_documented if {
	input.fisma.authorize.decision.authorizing_official_decision in ["authorize", "deny", "interim_authorize"]
	input.fisma.authorize.decision.decision_rationale_documented == true
	input.fisma.authorize.decision.authorization_letter_issued == true
}

terms_conditions_established if {
	input.fisma.authorize.terms_conditions.authorization_boundary_defined == true
	input.fisma.authorize.terms_conditions.authorization_period_defined == true
	input.fisma.authorize.terms_conditions.conditions_compliance_required == true
	input.fisma.authorize.terms_conditions.reporting_requirements_defined == true
}

# RMF Step 7: MONITOR - Monitor security controls on an ongoing basis
rmf_step_7_monitor_compliant if {
	continuous_monitoring_implemented
	configuration_management_monitored
	security_status_reporting_current
	ongoing_risk_assessments_conducted
}

continuous_monitoring_implemented if {
	input.fisma.monitor.continuous_monitoring.strategy_implemented == true
	input.fisma.monitor.continuous_monitoring.automated_tools_deployed == true
	input.fisma.monitor.continuous_monitoring.manual_assessments_scheduled == true
	input.fisma.monitor.continuous_monitoring.frequency_requirements_met == true
}

configuration_management_monitored if {
	input.fisma.monitor.configuration_management.baseline_configurations_maintained == true
	input.fisma.monitor.configuration_management.change_control_enforced == true
	input.fisma.monitor.configuration_management.configuration_deviations_tracked == true
	input.fisma.monitor.configuration_management.unauthorized_changes_detected == true
}

security_status_reporting_current if {
	input.fisma.monitor.reporting.security_status_reports_current == true
	input.fisma.monitor.reporting.metrics_collection_automated == true
	input.fisma.monitor.reporting.dashboard_updates_current == true
	input.fisma.monitor.reporting.escalation_procedures_followed == true
}

ongoing_risk_assessments_conducted if {
	input.fisma.monitor.ongoing_assessments.risk_reassessments_scheduled == true
	input.fisma.monitor.ongoing_assessments.control_assessments_ongoing == true
	input.fisma.monitor.ongoing_assessments.threat_intelligence_integrated == true
	input.fisma.monitor.ongoing_assessments.vulnerability_assessments_current == true
}

# FISMA Compliance Scoring
fisma_compliance_score := score if {
	total_checks := 7
	passed_checks := count([check |
		checks := [
			rmf_step_1_prepare_compliant,
			rmf_step_2_categorize_compliant,
			rmf_step_3_select_compliant,
			rmf_step_4_implement_compliant,
			rmf_step_5_assess_compliant,
			rmf_step_6_authorize_compliant,
			rmf_step_7_monitor_compliant,
		]
		check := checks[_]
		check == true
	])
	score := (passed_checks * 100) / total_checks
}

# FISMA Violations
fisma_violations := violations if {
	prepare_violations := [violation |
		not rmf_step_1_prepare_compliant
		violation := {
			"rmf_step": "RMF-P",
			"step_name": "Prepare",
			"severity": "high",
			"description": "Organizational preparation for risk management is incomplete",
			"remediation": "Complete risk strategy, role assignments, and common control identification",
		}
	]

	categorize_violations := [violation |
		not rmf_step_2_categorize_compliant
		violation := {
			"rmf_step": "RMF-C",
			"step_name": "Categorize", 
			"severity": "critical",
			"description": "System security categorization is incomplete or incorrect",
			"remediation": "Complete FIPS 199 categorization and obtain required approvals",
		}
	]

	select_violations := [violation |
		not rmf_step_3_select_compliant
		violation := {
			"rmf_step": "RMF-S",
			"step_name": "Select",
			"severity": "high",
			"description": "Security control selection and tailoring is incomplete",
			"remediation": "Apply appropriate control baselines and complete tailoring decisions",
		}
	]

	implement_violations := [violation |
		not rmf_step_4_implement_compliant
		violation := {
			"rmf_step": "RMF-I",
			"step_name": "Implement",
			"severity": "critical",
			"description": "Security control implementation is incomplete",
			"remediation": "Complete control implementation and develop System Security Plan",
		}
	]

	assess_violations := [violation |
		not rmf_step_5_assess_compliant
		violation := {
			"rmf_step": "RMF-A",
			"step_name": "Assess",
			"severity": "high",
			"description": "Security control assessment is incomplete",
			"remediation": "Complete independent assessment and document findings",
		}
	]

	authorize_violations := [violation |
		not rmf_step_6_authorize_compliant
		violation := {
			"rmf_step": "RMF-R",
			"step_name": "Authorize",
			"severity": "critical",
			"description": "System authorization is incomplete or expired",
			"remediation": "Complete authorization package and obtain ATO decision",
		}
	]

	monitor_violations := [violation |
		not rmf_step_7_monitor_compliant
		violation := {
			"rmf_step": "RMF-M",
			"step_name": "Monitor",
			"severity": "high",
			"description": "Continuous monitoring is not properly implemented",
			"remediation": "Implement continuous monitoring strategy and maintain current security status",
		}
	]

	violations := array.concat(prepare_violations, array.concat(categorize_violations, array.concat(select_violations, array.concat(implement_violations, array.concat(assess_violations, array.concat(authorize_violations, monitor_violations))))))
}

# FISMA Compliance Level Determination
fisma_compliance_level := "COMPLIANT" if {
	fisma_compliance_score >= 95
}

fisma_compliance_level := "SUBSTANTIALLY_COMPLIANT" if {
	fisma_compliance_score >= 85
	fisma_compliance_score < 95
}

fisma_compliance_level := "PARTIALLY_COMPLIANT" if {
	fisma_compliance_score >= 70
	fisma_compliance_score < 85
}

fisma_compliance_level := "NON_COMPLIANT" if {
	fisma_compliance_score < 70
}

# Authorization Status Determination
authorization_status := "AUTHORIZED" if {
	input.fisma.authorize.decision.authorizing_official_decision == "authorize"
	input.fisma.authorize.decision.authorization_expiration_date != ""
	# Check if authorization is not expired (simplified check)
	input.fisma.authorize.decision.authorization_current == true
}

authorization_status := "INTERIM_AUTHORIZED" if {
	input.fisma.authorize.decision.authorizing_official_decision == "interim_authorize"
	input.fisma.authorize.decision.interim_conditions_met == true
}

authorization_status := "DENIED" if {
	input.fisma.authorize.decision.authorizing_official_decision == "deny"
}

authorization_status := "NOT_AUTHORIZED" if {
	not input.fisma.authorize.decision.authorizing_official_decision
}

authorization_status := "EXPIRED" if {
	input.fisma.authorize.decision.authorizing_official_decision == "authorize"
	input.fisma.authorize.decision.authorization_current == false
}

# FISMA Assessment Report  
fisma_assessment := {
	"compliance_status": fisma_compliant == true,
	"compliance_score": fisma_compliance_score,
	"compliance_level": fisma_compliance_level,
	"rmf_steps": [
		{
			"step": "RMF-P",
			"name": "Prepare",
			"compliant": rmf_step_1_prepare_compliant == true,
			"description": "Essential activities to prepare the organization to manage security and privacy risks",
		},
		{
			"step": "RMF-C", 
			"name": "Categorize",
			"compliant": rmf_step_2_categorize_compliant == true,
			"description": "Categorize the system and information processed, stored, and transmitted",
		},
		{
			"step": "RMF-S",
			"name": "Select",
			"compliant": rmf_step_3_select_compliant == true,
			"description": "Select the set of NIST SP 800-53 controls to protect the system",
		},
		{
			"step": "RMF-I",
			"name": "Implement", 
			"compliant": rmf_step_4_implement_compliant == true,
			"description": "Implement the controls and document how controls are deployed",
		},
		{
			"step": "RMF-A",
			"name": "Assess",
			"compliant": rmf_step_5_assess_compliant == true,
			"description": "Assess the controls to determine if they are implemented correctly and effective",
		},
		{
			"step": "RMF-R",
			"name": "Authorize",
			"compliant": rmf_step_6_authorize_compliant == true,
			"description": "Make a risk-based decision to authorize the system to operate",
		},
		{
			"step": "RMF-M",
			"name": "Monitor",
			"compliant": rmf_step_7_monitor_compliant == true,
			"description": "Monitor the system and its controls on an ongoing basis",
		},
	],
	"total_violations": count(fisma_violations),
	"violations": fisma_violations,
}

# FISMA Metadata
fisma_metadata := {
	"framework_name": "Federal Information Security Modernization Act (FISMA)",
	"version": "2014",
	"implementation_standard": "NIST Risk Management Framework (RMF)",
	"control_catalog": "NIST SP 800-53 Revision 5", 
	"last_updated": "2025-01-06",
	"regulatory_authority": "Office of Management and Budget (OMB)",
	"applicable_entities": ["Federal agencies", "Federal contractors", "Federal information systems"],
	"enforcement_mechanism": "OMB oversight and reporting requirements",
	"penalties": "Varies by agency policy and contract requirements",
	"scope": "All federal information systems and data",
}