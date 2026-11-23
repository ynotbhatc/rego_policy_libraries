# METADATA
# title: "SOX IT General Controls (ITGC)"
# custom:
#   class: compliance
#   framework: sox
#   source: us-federal
#   domains: [financial, public-company]
#   coverage:
#     checks: 28
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package sox.itgc

import rego.v1

# SOX IT General Controls (ITGC)
# Core IT infrastructure controls supporting financial reporting systems

# IT General Controls Compliance Assessment
default itgc_compliant := false

itgc_compliant if {
	access_controls_compliant
	change_management_compliant
	computer_operations_compliant
	system_development_compliant
	data_center_operations_compliant
	backup_recovery_compliant

	# itgc_compliance_score includes this family, so the verdict must too
	financial_application_itgc_compliant
}

# Access Controls (ITGC-AC)
default access_controls_compliant := false

access_controls_compliant if {
	data.sox.itgc.access_controls.implemented == true
	logical_access_controls_effective
	privileged_access_controlled
	access_reviews_current
	segregation_of_duties_enforced
}

default logical_access_controls_effective := false

logical_access_controls_effective if {
	data.sox.itgc.logical_access.unique_user_ids.required == true
	data.sox.itgc.logical_access.strong_authentication.enforced == true
	data.sox.itgc.logical_access.password_policy.compliant == true
	data.sox.itgc.logical_access.session_management.secure == true
	data.sox.itgc.logical_access.account_lockout.configured == true
}

default privileged_access_controlled := false

privileged_access_controlled if {
	data.sox.itgc.privileged_access.admin_accounts.monitored == true
	data.sox.itgc.privileged_access.elevated_permissions.justified == true
	data.sox.itgc.privileged_access.access_logging.comprehensive == true
	data.sox.itgc.privileged_access.approval_workflow.documented == true
}

default access_reviews_current := false

access_reviews_current if {
	data.sox.itgc.access_reviews.quarterly_review.completed == true
	data.sox.itgc.access_reviews.terminated_users.removed_timely == true
	data.sox.itgc.access_reviews.role_changes.updated_promptly == true
	data.sox.itgc.access_reviews.exceptions.documented == true
}

default segregation_of_duties_enforced := false

segregation_of_duties_enforced if {
	data.sox.itgc.segregation_of_duties.development_production.separated == true
	data.sox.itgc.segregation_of_duties.financial_it.separated == true
	data.sox.itgc.segregation_of_duties.conflicting_roles.prevented == true
	data.sox.itgc.segregation_of_duties.compensating_controls.implemented == true
}

# Change Management (ITGC-CM)
default change_management_compliant := false

change_management_compliant if {
	data.sox.itgc.change_management.controlled == true
	change_approval_process_effective
	change_testing_comprehensive
	emergency_changes_controlled
	change_documentation_complete
}

default change_approval_process_effective := false

change_approval_process_effective if {
	data.sox.itgc.change_approval.business_approval.required == true
	data.sox.itgc.change_approval.technical_approval.required == true
	data.sox.itgc.change_approval.security_review.completed == true
	data.sox.itgc.change_approval.impact_assessment.documented == true
	data.sox.itgc.change_approval.rollback_plan.prepared == true
}

default change_testing_comprehensive := false

change_testing_comprehensive if {
	data.sox.itgc.change_testing.development_testing.completed == true
	data.sox.itgc.change_testing.user_acceptance_testing.passed == true
	data.sox.itgc.change_testing.performance_testing.satisfactory == true
	data.sox.itgc.change_testing.security_testing.passed == true
	data.sox.itgc.change_testing.regression_testing.completed == true
}

default emergency_changes_controlled := false

emergency_changes_controlled if {
	data.sox.itgc.emergency_changes.approval_process.expedited == true
	data.sox.itgc.emergency_changes.documentation.post_implementation == true
	data.sox.itgc.emergency_changes.review_process.timely == true
	data.sox.itgc.emergency_changes.permanent_fix.implemented == true
}

default change_documentation_complete := false

change_documentation_complete if {
	data.sox.itgc.change_documentation.requirements.documented == true
	data.sox.itgc.change_documentation.design_specifications.complete == true
	data.sox.itgc.change_documentation.test_results.recorded == true
	data.sox.itgc.change_documentation.implementation_guide.available == true
}

# Computer Operations (ITGC-CO)
default computer_operations_compliant := false

computer_operations_compliant if {
	data.sox.itgc.computer_operations.monitored == true
	system_monitoring_effective
	incident_management_robust
	capacity_management_adequate
	performance_monitoring_continuous
}

default system_monitoring_effective := false

system_monitoring_effective if {
	data.sox.itgc.system_monitoring.availability_monitoring.real_time == true
	data.sox.itgc.system_monitoring.performance_monitoring.continuous == true
	data.sox.itgc.system_monitoring.error_monitoring.automated == true
	data.sox.itgc.system_monitoring.security_monitoring.comprehensive == true
	data.sox.itgc.system_monitoring.alerting.immediate == true
}

default incident_management_robust := false

incident_management_robust if {
	data.sox.itgc.incident_management.incident_detection.automated == true
	data.sox.itgc.incident_management.response_procedures.documented == true
	data.sox.itgc.incident_management.escalation_process.defined == true
	data.sox.itgc.incident_management.resolution_tracking.maintained == true
	data.sox.itgc.incident_management.post_incident_review.conducted == true
}

default capacity_management_adequate := false

capacity_management_adequate if {
	data.sox.itgc.capacity_management.capacity_planning.annual == true
	data.sox.itgc.capacity_management.resource_monitoring.continuous == true
	data.sox.itgc.capacity_management.growth_projections.documented == true
	data.sox.itgc.capacity_management.scalability_testing.periodic == true
}

default performance_monitoring_continuous := false

performance_monitoring_continuous if {
	data.sox.itgc.performance_monitoring.response_time.monitored == true
	data.sox.itgc.performance_monitoring.throughput.measured == true
	data.sox.itgc.performance_monitoring.resource_utilization.tracked == true
	data.sox.itgc.performance_monitoring.trend_analysis.performed == true
}

# System Development (ITGC-SD)
default system_development_compliant := false

system_development_compliant if {
	data.sox.itgc.system_development.secure == true
	sdlc_process_defined
	security_requirements_integrated
	code_review_mandatory
	deployment_process_controlled
}

default sdlc_process_defined := false

sdlc_process_defined if {
	data.sox.itgc.sdlc.methodology.documented == true
	data.sox.itgc.sdlc.phases.clearly_defined == true
	data.sox.itgc.sdlc.deliverables.specified == true
	data.sox.itgc.sdlc.quality_gates.implemented == true
	data.sox.itgc.sdlc.approval_checkpoints.required == true
}

default security_requirements_integrated := false

security_requirements_integrated if {
	data.sox.itgc.security_requirements.threat_modeling.conducted == true
	data.sox.itgc.security_requirements.security_controls.designed == true
	data.sox.itgc.security_requirements.vulnerability_assessment.performed == true
	data.sox.itgc.security_requirements.penetration_testing.completed == true
}

default code_review_mandatory := false

code_review_mandatory if {
	data.sox.itgc.code_review.peer_review.required == true
	data.sox.itgc.code_review.security_review.mandatory == true
	data.sox.itgc.code_review.automated_scanning.performed == true
	data.sox.itgc.code_review.findings_remediation.tracked == true
}

default deployment_process_controlled := false

deployment_process_controlled if {
	data.sox.itgc.deployment.automated_deployment.implemented == true
	data.sox.itgc.deployment.environment_consistency.maintained == true
	data.sox.itgc.deployment.rollback_capability.tested == true
	data.sox.itgc.deployment.deployment_verification.automated == true
}

# Data Center Operations (ITGC-DCO)
default data_center_operations_compliant := false

data_center_operations_compliant if {
	data.sox.itgc.data_center_operations.controlled == true
	physical_security_adequate
	environmental_controls_effective
	power_systems_redundant
	network_infrastructure_secure
}

default physical_security_adequate := false

physical_security_adequate if {
	data.sox.itgc.physical_security.access_controls.multi_factor == true
	data.sox.itgc.physical_security.visitor_management.controlled == true
	data.sox.itgc.physical_security.surveillance.comprehensive == true
	data.sox.itgc.physical_security.access_logging.complete == true
	data.sox.itgc.physical_security.security_guards.present == true
}

default environmental_controls_effective := false

environmental_controls_effective if {
	data.sox.itgc.environmental.temperature_control.monitored == true
	data.sox.itgc.environmental.humidity_control.maintained == true
	data.sox.itgc.environmental.fire_suppression.tested == true
	data.sox.itgc.environmental.water_detection.implemented == true
	data.sox.itgc.environmental.air_quality.monitored == true
}

default power_systems_redundant := false

power_systems_redundant if {
	data.sox.itgc.power_systems.ups_systems.redundant == true
	data.sox.itgc.power_systems.backup_generators.tested == true
	data.sox.itgc.power_systems.power_monitoring.continuous == true
	data.sox.itgc.power_systems.load_balancing.implemented == true
}

default network_infrastructure_secure := false

network_infrastructure_secure if {
	data.sox.itgc.network.network_segmentation.implemented == true
	data.sox.itgc.network.firewall_management.controlled == true
	data.sox.itgc.network.intrusion_detection.deployed == true
	data.sox.itgc.network.network_monitoring.comprehensive == true
}

# Backup and Recovery (ITGC-BR)
default backup_recovery_compliant := false

backup_recovery_compliant if {
	data.sox.itgc.backup_recovery.tested == true
	backup_procedures_comprehensive
	recovery_procedures_tested
	disaster_recovery_planned
	business_continuity_ensured
}

default backup_procedures_comprehensive := false

backup_procedures_comprehensive if {
	data.sox.itgc.backup.backup_frequency.appropriate == true
	data.sox.itgc.backup.backup_verification.automated == true
	data.sox.itgc.backup.offsite_storage.implemented == true
	data.sox.itgc.backup.backup_encryption.enforced == true
	data.sox.itgc.backup.retention_policy.documented == true
}

default recovery_procedures_tested := false

recovery_procedures_tested if {
	data.sox.itgc.recovery.recovery_testing.quarterly == true
	data.sox.itgc.recovery.recovery_time_objectives.met == true
	data.sox.itgc.recovery.recovery_point_objectives.achieved == true
	data.sox.itgc.recovery.recovery_documentation.current == true
}

default disaster_recovery_planned := false

disaster_recovery_planned if {
	data.sox.itgc.disaster_recovery.dr_plan.documented == true
	data.sox.itgc.disaster_recovery.dr_site.configured == true
	data.sox.itgc.disaster_recovery.dr_testing.annual == true
	data.sox.itgc.disaster_recovery.communication_plan.defined == true
}

default business_continuity_ensured := false

business_continuity_ensured if {
	data.sox.itgc.business_continuity.bcp_plan.documented == true
	data.sox.itgc.business_continuity.impact_analysis.current == true
	data.sox.itgc.business_continuity.alternative_processes.defined == true
	data.sox.itgc.business_continuity.staff_training.conducted == true
}

# Financial Application-Specific ITGC
default financial_application_itgc_compliant := false

financial_application_itgc_compliant if {
	financial_system_access_controlled
	financial_data_integrity_maintained
	financial_processing_controls_effective
	financial_reporting_systems_secure
}

default financial_system_access_controlled := false

financial_system_access_controlled if {
	data.sox.financial_systems.access_controls.role_based == true
	data.sox.financial_systems.privileged_access.restricted == true
	data.sox.financial_systems.access_monitoring.real_time == true
	data.sox.financial_systems.access_certification.quarterly == true
}

default financial_data_integrity_maintained := false

financial_data_integrity_maintained if {
	data.sox.financial_data.data_validation.comprehensive == true
	data.sox.financial_data.data_reconciliation.automated == true
	data.sox.financial_data.data_archival.secure == true
	data.sox.financial_data.data_retention.compliant == true
}

default financial_processing_controls_effective := false

financial_processing_controls_effective if {
	data.sox.financial_processing.transaction_processing.controlled == true
	data.sox.financial_processing.batch_processing.monitored == true
	data.sox.financial_processing.exception_handling.documented == true
	data.sox.financial_processing.processing_completeness.verified == true
}

default financial_reporting_systems_secure := false

financial_reporting_systems_secure if {
	data.sox.financial_reporting.report_generation.controlled == true
	data.sox.financial_reporting.report_distribution.authorized == true
	data.sox.financial_reporting.report_archival.secure == true
	data.sox.financial_reporting.report_integrity.maintained == true
}

# ITGC Compliance Score Calculation
itgc_compliance_score := score if {
	components := [
		access_controls_score,
		change_management_score,
		computer_operations_score,
		system_development_score,
		data_center_operations_score,
		backup_recovery_score,
		financial_application_score,
	]
	score := (sum(components) / count(components)) * 100
}

# The family scores are defined with their check lists below.

# ITGC Risk Assessment
itgc_risk_level := "LOW" if {
	is_number(itgc_compliance_score)
	itgc_compliance_score >= 90
}

itgc_risk_level := "MEDIUM" if {
	is_number(itgc_compliance_score)
	itgc_compliance_score >= 75
	itgc_compliance_score < 90
}

itgc_risk_level := "HIGH" if {
	is_number(itgc_compliance_score)
	itgc_compliance_score >= 60
	itgc_compliance_score < 75
}

itgc_risk_level := "CRITICAL" if {
	is_number(itgc_compliance_score)
	itgc_compliance_score < 60
}

# ITGC Control Effectiveness Assessment
itgc_control_effectiveness := effectiveness if {
	effectiveness := {
		"access_controls": {
			"effectiveness": access_controls_score * 100,
			"status": _get_control_status(access_controls_score),
			"key_findings": _get_access_control_findings,
		},
		"change_management": {
			"effectiveness": change_management_score * 100,
			"status": _get_control_status(change_management_score),
			"key_findings": _get_change_management_findings,
		},
		"computer_operations": {
			"effectiveness": computer_operations_score * 100,
			"status": _get_control_status(computer_operations_score),
			"key_findings": _get_computer_operations_findings,
		},
		"system_development": {
			"effectiveness": system_development_score * 100,
			"status": _get_control_status(system_development_score),
			"key_findings": _get_system_development_findings,
		},
		"data_center_operations": {
			"effectiveness": data_center_operations_score * 100,
			"status": _get_control_status(data_center_operations_score),
			"key_findings": _get_data_center_findings,
		},
		"backup_recovery": {
			"effectiveness": backup_recovery_score * 100,
			"status": _get_control_status(backup_recovery_score),
			"key_findings": _get_backup_recovery_findings,
		},
		"financial_applications": {
			"effectiveness": financial_application_score * 100,
			"status": _get_control_status(financial_application_score),
			"key_findings": _get_financial_application_findings,
		},
	}
}

# Helper functions for control status
_get_control_status(score) := "EFFECTIVE" if {
	is_number(score)
	score >= 0.9
}

_get_control_status(score) := "PARTIALLY_EFFECTIVE" if {
	is_number(score)
	score >= 0.7
	score < 0.9
}

_get_control_status(score) := "INEFFECTIVE" if {
	is_number(score)
	score < 0.7
}

# Findings generation functions
default _access_control_attested := false

_access_control_attested if data.sox.itgc.access_controls.implemented == true

_access_control_checks := [
	{"check": _access_control_attested, "message": "Access controls are not attested as in place (data.sox.itgc.access_controls.implemented)"},
	{"check": logical_access_controls_effective, "message": "Logical access controls require strengthening"},
	{"check": privileged_access_controlled, "message": "Privileged access management needs improvement"},
	{"check": access_reviews_current, "message": "Access review processes are not current"},
	{"check": segregation_of_duties_enforced, "message": "Segregation of duties enforcement is inadequate"},
]

access_controls_score := _score(_access_control_checks)

_get_access_control_findings := _failed_messages(_access_control_checks)

default _change_management_attested := false

_change_management_attested if data.sox.itgc.change_management.controlled == true

_change_management_checks := [
	{"check": _change_management_attested, "message": "Change management controls are not attested as in place (data.sox.itgc.change_management.controlled)"},
	{"check": change_approval_process_effective, "message": "Change approval process needs enhancement"},
	{"check": change_testing_comprehensive, "message": "Change testing procedures are incomplete"},
	{"check": emergency_changes_controlled, "message": "Emergency change controls are insufficient"},
	{"check": change_documentation_complete, "message": "Change documentation is incomplete"},
]

change_management_score := _score(_change_management_checks)

_get_change_management_findings := _failed_messages(_change_management_checks)

default _computer_operations_attested := false

_computer_operations_attested if data.sox.itgc.computer_operations.monitored == true

_computer_operations_checks := [
	{"check": _computer_operations_attested, "message": "Computer operations controls are not attested as in place (data.sox.itgc.computer_operations.monitored)"},
	{"check": system_monitoring_effective, "message": "System monitoring capabilities need improvement"},
	{"check": incident_management_robust, "message": "Incident management process requires strengthening"},
	{"check": capacity_management_adequate, "message": "Capacity management practices are inadequate"},
	{"check": performance_monitoring_continuous, "message": "Performance monitoring is not continuous"},
]

computer_operations_score := _score(_computer_operations_checks)

_get_computer_operations_findings := _failed_messages(_computer_operations_checks)

default _system_development_attested := false

_system_development_attested if data.sox.itgc.system_development.secure == true

_system_development_checks := [
	{"check": _system_development_attested, "message": "System development controls are not attested as in place (data.sox.itgc.system_development.secure)"},
	{"check": sdlc_process_defined, "message": "SDLC process definition is incomplete"},
	{"check": security_requirements_integrated, "message": "Security requirements integration is insufficient"},
	{"check": code_review_mandatory, "message": "Code review process is not mandatory"},
	{"check": deployment_process_controlled, "message": "Deployment process controls are inadequate"},
]

system_development_score := _score(_system_development_checks)

_get_system_development_findings := _failed_messages(_system_development_checks)

default _data_center_attested := false

_data_center_attested if data.sox.itgc.data_center_operations.controlled == true

_data_center_checks := [
	{"check": _data_center_attested, "message": "Data center operations controls are not attested as in place (data.sox.itgc.data_center_operations.controlled)"},
	{"check": physical_security_adequate, "message": "Physical security controls need improvement"},
	{"check": environmental_controls_effective, "message": "Environmental controls are not effective"},
	{"check": power_systems_redundant, "message": "Power systems redundancy is insufficient"},
	{"check": network_infrastructure_secure, "message": "Network infrastructure security requires enhancement"},
]

data_center_operations_score := _score(_data_center_checks)

_get_data_center_findings := _failed_messages(_data_center_checks)

default _backup_recovery_attested := false

_backup_recovery_attested if data.sox.itgc.backup_recovery.tested == true

_backup_recovery_checks := [
	{"check": _backup_recovery_attested, "message": "Backup and recovery controls are not attested as in place (data.sox.itgc.backup_recovery.tested)"},
	{"check": backup_procedures_comprehensive, "message": "Backup procedures are not comprehensive"},
	{"check": recovery_procedures_tested, "message": "Recovery procedures testing is inadequate"},
	{"check": disaster_recovery_planned, "message": "Disaster recovery planning is incomplete"},
	{"check": business_continuity_ensured, "message": "Business continuity assurance is insufficient"},
]

backup_recovery_score := _score(_backup_recovery_checks)

_get_backup_recovery_findings := _failed_messages(_backup_recovery_checks)

_financial_application_checks := [
	{"check": financial_system_access_controlled, "message": "Financial system access controls need strengthening"},
	{"check": financial_data_integrity_maintained, "message": "Financial data integrity controls are inadequate"},
	{"check": financial_processing_controls_effective, "message": "Financial processing controls are not effective"},
	{"check": financial_reporting_systems_secure, "message": "Financial reporting system security needs improvement"},
]

financial_application_score := _score(_financial_application_checks)

_get_financial_application_findings := _failed_messages(_financial_application_checks)

# ---------------------------------------------------------------------------
# One list of checks per family feeds that family's score and its findings, and the lists together feed the
# counts, so passed + failed = total on every input. A check passes only when it is true; a fact that is
# absent, null or not the boolean true fails it.
# ---------------------------------------------------------------------------

_score(checks) := count([check | some check in checks; check.check == true]) / count(checks)

_failed_messages(checks) := [check.message | some check in checks; check.check != true]

_all_checks := [check |
	some family in [
		_access_control_checks,
		_change_management_checks,
		_computer_operations_checks,
		_system_development_checks,
		_data_center_checks,
		_backup_recovery_checks,
		_financial_application_checks,
	]
	some check in family
]

control_counts := {
	"total_controls": count(_all_checks),
	"passed_controls": count([check | some check in _all_checks; check.check == true]),
	"failed_controls": count(_failed_messages(_all_checks)),
}
