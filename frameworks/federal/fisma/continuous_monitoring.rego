package fisma.continuous_monitoring

import rego.v1

# FISMA Continuous Monitoring Program
# NIST SP 800-137 - Information Security Continuous Monitoring (ISCM) for Federal Information Systems
# RMF Step 7: Monitor security controls on an ongoing basis

# Main Continuous Monitoring Compliance
continuous_monitoring_compliant if {
	iscm_program_established
	continuous_monitoring_strategy_implemented
	security_status_monitoring_active
	ongoing_assessments_conducted
	incident_response_integrated
	reporting_requirements_met
}

# ISCM Program Establishment
iscm_program_established if {
	iscm_program_documented
	iscm_roles_responsibilities_defined
	iscm_automation_capabilities_implemented
	iscm_metrics_defined
}

iscm_program_documented if {
	input.continuous_monitoring.program.iscm_strategy_documented == true
	input.continuous_monitoring.program.scope_defined == true
	input.continuous_monitoring.program.objectives_stated == true
	input.continuous_monitoring.program.governance_structure_established == true
	input.continuous_monitoring.program.risk_tolerance_defined == true
}

iscm_roles_responsibilities_defined if {
	input.continuous_monitoring.roles.iscm_program_manager.assigned == true
	input.continuous_monitoring.roles.system_owners.responsibilities_defined == true
	input.continuous_monitoring.roles.security_control_assessors.responsibilities_defined == true
	input.continuous_monitoring.roles.authorizing_officials.responsibilities_defined == true
	input.continuous_monitoring.roles.risk_executive.responsibilities_defined == true
}

iscm_automation_capabilities_implemented if {
	input.continuous_monitoring.automation.automated_tools_deployed == true
	input.continuous_monitoring.automation.tool_integration_implemented == true
	input.continuous_monitoring.automation.automated_data_collection == true
	input.continuous_monitoring.automation.automated_analysis_capabilities == true
	input.continuous_monitoring.automation.dashboard_capabilities == true
}

iscm_metrics_defined if {
	count(input.continuous_monitoring.metrics.security_metrics) > 0
	every metric in input.continuous_monitoring.metrics.security_metrics {
		metric.metric_name != ""
		metric.measurement_method != ""
		metric.frequency != ""
		metric.target_value != ""
		metric.responsible_party != ""
	}
}

# Continuous Monitoring Strategy Implementation
continuous_monitoring_strategy_implemented if {
	monitoring_frequencies_established
	monitoring_procedures_documented
	monitoring_scope_defined
	monitoring_tools_configured
}

monitoring_frequencies_established if {
	input.continuous_monitoring.strategy.configuration_monitoring.frequency in ["real_time", "daily", "weekly"]
	input.continuous_monitoring.strategy.vulnerability_scanning.frequency in ["weekly", "monthly", "quarterly"]
	input.continuous_monitoring.strategy.control_assessments.frequency in ["annually", "bi_annually", "quarterly"]
	input.continuous_monitoring.strategy.penetration_testing.frequency in ["annually", "bi_annually"]
}

monitoring_procedures_documented if {
	input.continuous_monitoring.procedures.configuration_monitoring_procedures == true
	input.continuous_monitoring.procedures.vulnerability_assessment_procedures == true
	input.continuous_monitoring.procedures.malware_detection_procedures == true
	input.continuous_monitoring.procedures.network_monitoring_procedures == true
	input.continuous_monitoring.procedures.log_analysis_procedures == true
}

monitoring_scope_defined if {
	count(input.continuous_monitoring.scope.monitored_systems) > 0
	every system in input.continuous_monitoring.scope.monitored_systems {
		system.system_id != ""
		system.monitoring_level in ["basic", "standard", "enhanced"]
		system.critical_controls_identified == true
		system.monitoring_frequency_defined == true
	}
}

monitoring_tools_configured if {
	count(input.continuous_monitoring.tools.deployed_tools) > 0
	every tool in input.continuous_monitoring.tools.deployed_tools {
		tool.tool_name != ""
		tool.tool_type in ["vulnerability_scanner", "configuration_scanner", "network_monitor", "log_analyzer", "siem", "other"]
		tool.configuration_current == true
		tool.integration_status == "active"
		tool.coverage_adequate == true
	}
}

# Security Status Monitoring
security_status_monitoring_active if {
	configuration_management_monitoring
	vulnerability_management_monitoring
	security_controls_monitoring
	threat_intelligence_integration
}

configuration_management_monitoring if {
	input.continuous_monitoring.configuration.baseline_configurations_maintained == true
	input.continuous_monitoring.configuration.configuration_changes_tracked == true
	input.continuous_monitoring.configuration.unauthorized_changes_detected == true
	input.continuous_monitoring.configuration.configuration_drift_monitored == true
	input.continuous_monitoring.configuration.remediation_automated == true
}

vulnerability_management_monitoring if {
	input.continuous_monitoring.vulnerabilities.scanning_current == true
	input.continuous_monitoring.vulnerabilities.vulnerability_database_current == true
	input.continuous_monitoring.vulnerabilities.risk_scoring_implemented == true
	input.continuous_monitoring.vulnerabilities.remediation_tracking == true
	input.continuous_monitoring.vulnerabilities.false_positive_management == true
}

security_controls_monitoring if {
	input.continuous_monitoring.controls.control_effectiveness_monitored == true
	input.continuous_monitoring.controls.control_failures_detected == true
	input.continuous_monitoring.controls.compensating_controls_monitored == true
	input.continuous_monitoring.controls.control_inheritance_verified == true
}

threat_intelligence_integration if {
	input.continuous_monitoring.threat_intelligence.feeds_integrated == true
	input.continuous_monitoring.threat_intelligence.indicators_monitored == true
	input.continuous_monitoring.threat_intelligence.threat_hunting_conducted == true
	input.continuous_monitoring.threat_intelligence.attribution_analysis == true
}

# Ongoing Assessments
ongoing_assessments_conducted if {
	security_control_assessments_ongoing
	risk_assessments_current
	penetration_testing_scheduled
	red_team_exercises_conducted
}

security_control_assessments_ongoing if {
	input.continuous_monitoring.assessments.control_assessments.schedule_maintained == true
	input.continuous_monitoring.assessments.control_assessments.assessment_procedures_current == true
	input.continuous_monitoring.assessments.control_assessments.findings_tracked == true
	input.continuous_monitoring.assessments.control_assessments.remediation_monitored == true
}

risk_assessments_current if {
	input.continuous_monitoring.risk_assessments.risk_assessment_current == true
	input.continuous_monitoring.risk_assessments.threat_assessment_current == true
	input.continuous_monitoring.risk_assessments.vulnerability_assessment_current == true
	input.continuous_monitoring.risk_assessments.impact_analysis_current == true
}

penetration_testing_scheduled if {
	input.continuous_monitoring.penetration_testing.testing_scheduled == true
	input.continuous_monitoring.penetration_testing.scope_defined == true
	input.continuous_monitoring.penetration_testing.results_analyzed == true
	input.continuous_monitoring.penetration_testing.remediation_tracked == true
}

red_team_exercises_conducted if {
	input.continuous_monitoring.red_team.exercises_conducted == true
	input.continuous_monitoring.red_team.scenarios_realistic == true
	input.continuous_monitoring.red_team.findings_documented == true
	input.continuous_monitoring.red_team.improvements_implemented == true
}

# Incident Response Integration
incident_response_integrated if {
	incident_detection_capabilities
	incident_response_procedures_current
	incident_data_collection
	lessons_learned_integration
}

incident_detection_capabilities if {
	input.continuous_monitoring.incident_response.detection_capabilities.siem_deployed == true
	input.continuous_monitoring.incident_response.detection_capabilities.ids_ips_deployed == true
	input.continuous_monitoring.incident_response.detection_capabilities.endpoint_detection == true
	input.continuous_monitoring.incident_response.detection_capabilities.network_monitoring == true
	input.continuous_monitoring.incident_response.detection_capabilities.user_behavior_analytics == true
}

incident_response_procedures_current if {
	input.continuous_monitoring.incident_response.procedures.incident_response_plan_current == true
	input.continuous_monitoring.incident_response.procedures.escalation_procedures_defined == true
	input.continuous_monitoring.incident_response.procedures.containment_procedures_defined == true
	input.continuous_monitoring.incident_response.procedures.recovery_procedures_defined == true
}

incident_data_collection if {
	input.continuous_monitoring.incident_response.data_collection.forensic_capabilities == true
	input.continuous_monitoring.incident_response.data_collection.log_preservation == true
	input.continuous_monitoring.incident_response.data_collection.evidence_handling == true
	input.continuous_monitoring.incident_response.data_collection.chain_of_custody == true
}

lessons_learned_integration if {
	input.continuous_monitoring.incident_response.lessons_learned.post_incident_reviews == true
	input.continuous_monitoring.incident_response.lessons_learned.process_improvements == true
	input.continuous_monitoring.incident_response.lessons_learned.control_updates == true
	input.continuous_monitoring.incident_response.lessons_learned.training_updates == true
}

# Reporting Requirements
reporting_requirements_met if {
	management_reporting_current
	regulatory_reporting_compliant
	stakeholder_communication_effective
	performance_metrics_tracked
}

management_reporting_current if {
	input.continuous_monitoring.reporting.management.dashboard_current == true
	input.continuous_monitoring.reporting.management.executive_summaries_provided == true
	input.continuous_monitoring.reporting.management.trend_analysis_provided == true
	input.continuous_monitoring.reporting.management.risk_posture_reported == true
}

regulatory_reporting_compliant if {
	input.continuous_monitoring.reporting.regulatory.fisma_reporting_current == true
	input.continuous_monitoring.reporting.regulatory.omb_reporting_compliant == true
	input.continuous_monitoring.reporting.regulatory.agency_reporting_compliant == true
	input.continuous_monitoring.reporting.regulatory.timeline_compliance == true
}

stakeholder_communication_effective if {
	input.continuous_monitoring.reporting.stakeholder.authorizing_officials_informed == true
	input.continuous_monitoring.reporting.stakeholder.system_owners_informed == true
	input.continuous_monitoring.reporting.stakeholder.users_notified == true
	input.continuous_monitoring.reporting.stakeholder.feedback_mechanisms == true
}

performance_metrics_tracked if {
	input.continuous_monitoring.reporting.metrics.security_metrics_current == true
	input.continuous_monitoring.reporting.metrics.performance_trends_analyzed == true
	input.continuous_monitoring.reporting.metrics.benchmarking_conducted == true
	input.continuous_monitoring.reporting.metrics.improvement_recommendations == true
}

# Continuous Monitoring Maturity Assessment
continuous_monitoring_maturity_level := "LEVEL_1_INITIAL" if {
	continuous_monitoring_score >= 0
	continuous_monitoring_score < 40
}

continuous_monitoring_maturity_level := "LEVEL_2_DEVELOPING" if {
	continuous_monitoring_score >= 40
	continuous_monitoring_score < 60
}

continuous_monitoring_maturity_level := "LEVEL_3_DEFINED" if {
	continuous_monitoring_score >= 60
	continuous_monitoring_score < 80
}

continuous_monitoring_maturity_level := "LEVEL_4_MANAGED" if {
	continuous_monitoring_score >= 80
	continuous_monitoring_score < 95
}

continuous_monitoring_maturity_level := "LEVEL_5_OPTIMIZED" if {
	continuous_monitoring_score >= 95
}

# Continuous Monitoring Score
continuous_monitoring_score := score if {
	total_areas := 6
	passed_areas = count([area |
		areas = [
			iscm_program_established,
			continuous_monitoring_strategy_implemented,
			security_status_monitoring_active,
			ongoing_assessments_conducted,
			incident_response_integrated,
			reporting_requirements_met,
		]
		area = areas[_]
		area == true
	])
	score := (passed_areas * 100) / total_areas
}

# Continuous Monitoring Gaps
continuous_monitoring_gaps := gaps if {
	program_gaps = [gap |
		not iscm_program_established
		gap = {
			"area": "ISCM Program",
			"severity": "high",
			"description": "Information Security Continuous Monitoring program is not properly established",
			"remediation": "Develop ISCM strategy, define roles, implement automation, and establish metrics",
		}
	]

	strategy_gaps = [gap |
		not continuous_monitoring_strategy_implemented
		gap = {
			"area": "Monitoring Strategy",
			"severity": "high",
			"description": "Continuous monitoring strategy is not properly implemented",
			"remediation": "Establish monitoring frequencies, document procedures, define scope, and configure tools",
		}
	]

	monitoring_gaps = [gap |
		not security_status_monitoring_active
		gap = {
			"area": "Security Status Monitoring",
			"severity": "critical",
			"description": "Active security status monitoring is not in place",
			"remediation": "Implement configuration, vulnerability, control, and threat intelligence monitoring",
		}
	]

	assessment_gaps = [gap |
		not ongoing_assessments_conducted
		gap = {
			"area": "Ongoing Assessments",
			"severity": "high",
			"description": "Ongoing security assessments are not being conducted",
			"remediation": "Schedule control assessments, risk assessments, penetration testing, and red team exercises",
		}
	]

	incident_gaps = [gap |
		not incident_response_integrated
		gap = {
			"area": "Incident Response Integration",
			"severity": "critical",
			"description": "Incident response is not properly integrated with continuous monitoring",
			"remediation": "Implement detection capabilities, update procedures, establish data collection, and integrate lessons learned",
		}
	]

	reporting_gaps = [gap |
		not reporting_requirements_met
		gap = {
			"area": "Reporting Requirements",
			"severity": "medium",
			"description": "Continuous monitoring reporting requirements are not being met",
			"remediation": "Implement management reporting, ensure regulatory compliance, improve stakeholder communication, and track performance metrics",
		}
	]

	gaps := array.concat(program_gaps, array.concat(strategy_gaps, array.concat(monitoring_gaps, array.concat(assessment_gaps, array.concat(incident_gaps, reporting_gaps)))))
}

# Continuous Monitoring Assessment
continuous_monitoring_assessment := {
	"continuous_monitoring_compliant": continuous_monitoring_compliant == true,
	"maturity_level": continuous_monitoring_maturity_level,
	"monitoring_score": continuous_monitoring_score,
	"program_areas": [
		{
			"area": "ISCM Program",
			"compliant": iscm_program_established == true,
			"description": "Information Security Continuous Monitoring program establishment",
		},
		{
			"area": "Monitoring Strategy",
			"compliant": continuous_monitoring_strategy_implemented == true,
			"description": "Continuous monitoring strategy implementation",
		},
		{
			"area": "Security Status Monitoring",
			"compliant": security_status_monitoring_active == true,
			"description": "Active security status monitoring capabilities",
		},
		{
			"area": "Ongoing Assessments",
			"compliant": ongoing_assessments_conducted == true,
			"description": "Ongoing security assessments and testing",
		},
		{
			"area": "Incident Response Integration",
			"compliant": incident_response_integrated == true,
			"description": "Integration with incident response capabilities",
		},
		{
			"area": "Reporting Requirements",
			"compliant": reporting_requirements_met == true,
			"description": "Continuous monitoring reporting and communication",
		},
	],
	"total_gaps": count(continuous_monitoring_gaps),
	"gaps": continuous_monitoring_gaps,
}

# Continuous Monitoring Metadata
continuous_monitoring_metadata := {
	"standard": "NIST SP 800-137",
	"framework": "Information Security Continuous Monitoring (ISCM)",
	"rmf_step": "RMF-M (Monitor)",
	"purpose": "Ongoing monitoring of security controls and system security posture",
	"scope": "Federal information systems subject to FISMA requirements",
	"last_updated": "2025-01-06",
}