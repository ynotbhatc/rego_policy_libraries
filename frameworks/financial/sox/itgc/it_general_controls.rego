# METADATA
# title: "SOX IT General Controls (ITGC)"
# custom:
#   class: compliance
#   framework: sox
#   source: us-federal
#   domains: [financial, public-company]
#   coverage:
#     checks: 34
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.5.0
package sox.itgc

import rego.v1

# SOX IT General Controls (ITGC)
# Core IT infrastructure controls supporting financial reporting systems
#
# Facts are read from input.sox.<...>, the input document the caller posts (the fact paths are listed in _facts).
# When the input has no "sox" key, facts loaded as data.sox.<...> are read instead (the older way to feed this
# module). The two are never merged and input.sox always wins; control_counts states which one was read in
# evidence_source ("input", "data" or "none") and sets data_sox_ignored when both were present. Only the boolean
# true passes a fact; evidence_problems names every fact that is absent, null or not a boolean.

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
	_access_control_attested
	logical_access_controls_effective
	privileged_access_controlled
	access_reviews_current
	segregation_of_duties_enforced
}

default logical_access_controls_effective := false

logical_access_controls_effective if _all_true(_facts.logical_access_controls_effective)

default privileged_access_controlled := false

privileged_access_controlled if _all_true(_facts.privileged_access_controlled)

default access_reviews_current := false

access_reviews_current if _all_true(_facts.access_reviews_current)

default segregation_of_duties_enforced := false

segregation_of_duties_enforced if _all_true(_facts.segregation_of_duties_enforced)

# Change Management (ITGC-CM)
default change_management_compliant := false

change_management_compliant if {
	_change_management_attested
	change_approval_process_effective
	change_testing_comprehensive
	emergency_changes_controlled
	change_documentation_complete
}

default change_approval_process_effective := false

change_approval_process_effective if _all_true(_facts.change_approval_process_effective)

default change_testing_comprehensive := false

change_testing_comprehensive if _all_true(_facts.change_testing_comprehensive)

default emergency_changes_controlled := false

emergency_changes_controlled if _all_true(_facts.emergency_changes_controlled)

default change_documentation_complete := false

change_documentation_complete if _all_true(_facts.change_documentation_complete)

# Computer Operations (ITGC-CO)
default computer_operations_compliant := false

computer_operations_compliant if {
	_computer_operations_attested
	system_monitoring_effective
	incident_management_robust
	capacity_management_adequate
	performance_monitoring_continuous
}

default system_monitoring_effective := false

system_monitoring_effective if _all_true(_facts.system_monitoring_effective)

default incident_management_robust := false

incident_management_robust if _all_true(_facts.incident_management_robust)

default capacity_management_adequate := false

capacity_management_adequate if _all_true(_facts.capacity_management_adequate)

default performance_monitoring_continuous := false

performance_monitoring_continuous if _all_true(_facts.performance_monitoring_continuous)

# System Development (ITGC-SD)
default system_development_compliant := false

system_development_compliant if {
	_system_development_attested
	sdlc_process_defined
	security_requirements_integrated
	code_review_mandatory
	deployment_process_controlled
}

default sdlc_process_defined := false

sdlc_process_defined if _all_true(_facts.sdlc_process_defined)

default security_requirements_integrated := false

security_requirements_integrated if _all_true(_facts.security_requirements_integrated)

default code_review_mandatory := false

code_review_mandatory if _all_true(_facts.code_review_mandatory)

default deployment_process_controlled := false

deployment_process_controlled if _all_true(_facts.deployment_process_controlled)

# Data Center Operations (ITGC-DCO)
default data_center_operations_compliant := false

data_center_operations_compliant if {
	_data_center_attested
	physical_security_adequate
	environmental_controls_effective
	power_systems_redundant
	network_infrastructure_secure
}

default physical_security_adequate := false

physical_security_adequate if _all_true(_facts.physical_security_adequate)

default environmental_controls_effective := false

environmental_controls_effective if _all_true(_facts.environmental_controls_effective)

default power_systems_redundant := false

power_systems_redundant if _all_true(_facts.power_systems_redundant)

default network_infrastructure_secure := false

network_infrastructure_secure if _all_true(_facts.network_infrastructure_secure)

# Backup and Recovery (ITGC-BR)
default backup_recovery_compliant := false

backup_recovery_compliant if {
	_backup_recovery_attested
	backup_procedures_comprehensive
	recovery_procedures_tested
	disaster_recovery_planned
	business_continuity_ensured
}

default backup_procedures_comprehensive := false

backup_procedures_comprehensive if _all_true(_facts.backup_procedures_comprehensive)

default recovery_procedures_tested := false

recovery_procedures_tested if _all_true(_facts.recovery_procedures_tested)

default disaster_recovery_planned := false

disaster_recovery_planned if _all_true(_facts.disaster_recovery_planned)

default business_continuity_ensured := false

business_continuity_ensured if _all_true(_facts.business_continuity_ensured)

# Financial Application-Specific ITGC
default financial_application_itgc_compliant := false

financial_application_itgc_compliant if {
	financial_system_access_controlled
	financial_data_integrity_maintained
	financial_processing_controls_effective
	financial_reporting_systems_secure
}

default financial_system_access_controlled := false

financial_system_access_controlled if _all_true(_facts.financial_system_access_controlled)

default financial_data_integrity_maintained := false

financial_data_integrity_maintained if _all_true(_facts.financial_data_integrity_maintained)

default financial_processing_controls_effective := false

financial_processing_controls_effective if _all_true(_facts.financial_processing_controls_effective)

default financial_reporting_systems_secure := false

financial_reporting_systems_secure if _all_true(_facts.financial_reporting_systems_secure)

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
			"evidence_problems": _evidence_problems(_access_control_checks),
		},
		"change_management": {
			"effectiveness": change_management_score * 100,
			"status": _get_control_status(change_management_score),
			"key_findings": _get_change_management_findings,
			"evidence_problems": _evidence_problems(_change_management_checks),
		},
		"computer_operations": {
			"effectiveness": computer_operations_score * 100,
			"status": _get_control_status(computer_operations_score),
			"key_findings": _get_computer_operations_findings,
			"evidence_problems": _evidence_problems(_computer_operations_checks),
		},
		"system_development": {
			"effectiveness": system_development_score * 100,
			"status": _get_control_status(system_development_score),
			"key_findings": _get_system_development_findings,
			"evidence_problems": _evidence_problems(_system_development_checks),
		},
		"data_center_operations": {
			"effectiveness": data_center_operations_score * 100,
			"status": _get_control_status(data_center_operations_score),
			"key_findings": _get_data_center_findings,
			"evidence_problems": _evidence_problems(_data_center_checks),
		},
		"backup_recovery": {
			"effectiveness": backup_recovery_score * 100,
			"status": _get_control_status(backup_recovery_score),
			"key_findings": _get_backup_recovery_findings,
			"evidence_problems": _evidence_problems(_backup_recovery_checks),
		},
		"financial_applications": {
			"effectiveness": financial_application_score * 100,
			"status": _get_control_status(financial_application_score),
			"key_findings": _get_financial_application_findings,
			"evidence_problems": _evidence_problems(_financial_application_checks),
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

_access_control_attested if _all_true(_facts._access_control_attested)

_access_control_checks := [
	{"check": _access_control_attested, "rule": "_access_control_attested", "message": "Access controls are not attested as in place (sox.itgc.access_controls.implemented)"},
	{"check": logical_access_controls_effective, "rule": "logical_access_controls_effective", "message": "Logical access controls require strengthening"},
	{"check": privileged_access_controlled, "rule": "privileged_access_controlled", "message": "Privileged access management needs improvement"},
	{"check": access_reviews_current, "rule": "access_reviews_current", "message": "Access review processes are not current"},
	{"check": segregation_of_duties_enforced, "rule": "segregation_of_duties_enforced", "message": "Segregation of duties enforcement is inadequate"},
]

access_controls_score := _score(_access_control_checks)

_get_access_control_findings := _failed_messages(_access_control_checks)

default _change_management_attested := false

_change_management_attested if _all_true(_facts._change_management_attested)

_change_management_checks := [
	{"check": _change_management_attested, "rule": "_change_management_attested", "message": "Change management controls are not attested as in place (sox.itgc.change_management.controlled)"},
	{"check": change_approval_process_effective, "rule": "change_approval_process_effective", "message": "Change approval process needs enhancement"},
	{"check": change_testing_comprehensive, "rule": "change_testing_comprehensive", "message": "Change testing procedures are incomplete"},
	{"check": emergency_changes_controlled, "rule": "emergency_changes_controlled", "message": "Emergency change controls are insufficient"},
	{"check": change_documentation_complete, "rule": "change_documentation_complete", "message": "Change documentation is incomplete"},
]

change_management_score := _score(_change_management_checks)

_get_change_management_findings := _failed_messages(_change_management_checks)

default _computer_operations_attested := false

_computer_operations_attested if _all_true(_facts._computer_operations_attested)

_computer_operations_checks := [
	{"check": _computer_operations_attested, "rule": "_computer_operations_attested", "message": "Computer operations controls are not attested as in place (sox.itgc.computer_operations.monitored)"},
	{"check": system_monitoring_effective, "rule": "system_monitoring_effective", "message": "System monitoring capabilities need improvement"},
	{"check": incident_management_robust, "rule": "incident_management_robust", "message": "Incident management process requires strengthening"},
	{"check": capacity_management_adequate, "rule": "capacity_management_adequate", "message": "Capacity management practices are inadequate"},
	{"check": performance_monitoring_continuous, "rule": "performance_monitoring_continuous", "message": "Performance monitoring is not continuous"},
]

computer_operations_score := _score(_computer_operations_checks)

_get_computer_operations_findings := _failed_messages(_computer_operations_checks)

default _system_development_attested := false

_system_development_attested if _all_true(_facts._system_development_attested)

_system_development_checks := [
	{"check": _system_development_attested, "rule": "_system_development_attested", "message": "System development controls are not attested as in place (sox.itgc.system_development.secure)"},
	{"check": sdlc_process_defined, "rule": "sdlc_process_defined", "message": "SDLC process definition is incomplete"},
	{"check": security_requirements_integrated, "rule": "security_requirements_integrated", "message": "Security requirements integration is insufficient"},
	{"check": code_review_mandatory, "rule": "code_review_mandatory", "message": "Code review process is not mandatory"},
	{"check": deployment_process_controlled, "rule": "deployment_process_controlled", "message": "Deployment process controls are inadequate"},
]

system_development_score := _score(_system_development_checks)

_get_system_development_findings := _failed_messages(_system_development_checks)

default _data_center_attested := false

_data_center_attested if _all_true(_facts._data_center_attested)

_data_center_checks := [
	{"check": _data_center_attested, "rule": "_data_center_attested", "message": "Data center operations controls are not attested as in place (sox.itgc.data_center_operations.controlled)"},
	{"check": physical_security_adequate, "rule": "physical_security_adequate", "message": "Physical security controls need improvement"},
	{"check": environmental_controls_effective, "rule": "environmental_controls_effective", "message": "Environmental controls are not effective"},
	{"check": power_systems_redundant, "rule": "power_systems_redundant", "message": "Power systems redundancy is insufficient"},
	{"check": network_infrastructure_secure, "rule": "network_infrastructure_secure", "message": "Network infrastructure security requires enhancement"},
]

data_center_operations_score := _score(_data_center_checks)

_get_data_center_findings := _failed_messages(_data_center_checks)

default _backup_recovery_attested := false

_backup_recovery_attested if _all_true(_facts._backup_recovery_attested)

_backup_recovery_checks := [
	{"check": _backup_recovery_attested, "rule": "_backup_recovery_attested", "message": "Backup and recovery controls are not attested as in place (sox.itgc.backup_recovery.tested)"},
	{"check": backup_procedures_comprehensive, "rule": "backup_procedures_comprehensive", "message": "Backup procedures are not comprehensive"},
	{"check": recovery_procedures_tested, "rule": "recovery_procedures_tested", "message": "Recovery procedures testing is inadequate"},
	{"check": disaster_recovery_planned, "rule": "disaster_recovery_planned", "message": "Disaster recovery planning is incomplete"},
	{"check": business_continuity_ensured, "rule": "business_continuity_ensured", "message": "Business continuity assurance is insufficient"},
]

backup_recovery_score := _score(_backup_recovery_checks)

_get_backup_recovery_findings := _failed_messages(_backup_recovery_checks)

_financial_application_checks := [
	{"check": financial_system_access_controlled, "rule": "financial_system_access_controlled", "message": "Financial system access controls need strengthening"},
	{"check": financial_data_integrity_maintained, "rule": "financial_data_integrity_maintained", "message": "Financial data integrity controls are inadequate"},
	{"check": financial_processing_controls_effective, "rule": "financial_processing_controls_effective", "message": "Financial processing controls are not effective"},
	{"check": financial_reporting_systems_secure, "rule": "financial_reporting_systems_secure", "message": "Financial reporting system security needs improvement"},
]

financial_application_score := _score(_financial_application_checks)

_get_financial_application_findings := _failed_messages(_financial_application_checks)

# ---------------------------------------------------------------------------
# One list of checks per family feeds that family's score and its findings, and the lists together feed the
# counts, so passed + failed = total on every input. A check passes only when every fact it names in _facts is
# the boolean true; a fact that is absent, null or not a boolean fails it and is named in evidence_problems.
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
	"evidence_source": evidence_source,
	"data_sox_ignored": data_sox_ignored,
}

# The facts each check requires (dotted paths below sox). The rules above and the evidence problems read this
# one list.
_facts := {
	"logical_access_controls_effective": [
		"itgc.logical_access.unique_user_ids.required",
		"itgc.logical_access.strong_authentication.enforced",
		"itgc.logical_access.password_policy.compliant",
		"itgc.logical_access.session_management.secure",
		"itgc.logical_access.account_lockout.configured",
	],
	"privileged_access_controlled": [
		"itgc.privileged_access.admin_accounts.monitored",
		"itgc.privileged_access.elevated_permissions.justified",
		"itgc.privileged_access.access_logging.comprehensive",
		"itgc.privileged_access.approval_workflow.documented",
	],
	"access_reviews_current": [
		"itgc.access_reviews.quarterly_review.completed",
		"itgc.access_reviews.terminated_users.removed_timely",
		"itgc.access_reviews.role_changes.updated_promptly",
		"itgc.access_reviews.exceptions.documented",
	],
	"segregation_of_duties_enforced": [
		"itgc.segregation_of_duties.development_production.separated",
		"itgc.segregation_of_duties.financial_it.separated",
		"itgc.segregation_of_duties.conflicting_roles.prevented",
		"itgc.segregation_of_duties.compensating_controls.implemented",
	],
	"change_approval_process_effective": [
		"itgc.change_approval.business_approval.required",
		"itgc.change_approval.technical_approval.required",
		"itgc.change_approval.security_review.completed",
		"itgc.change_approval.impact_assessment.documented",
		"itgc.change_approval.rollback_plan.prepared",
	],
	"change_testing_comprehensive": [
		"itgc.change_testing.development_testing.completed",
		"itgc.change_testing.user_acceptance_testing.passed",
		"itgc.change_testing.performance_testing.satisfactory",
		"itgc.change_testing.security_testing.passed",
		"itgc.change_testing.regression_testing.completed",
	],
	"emergency_changes_controlled": [
		"itgc.emergency_changes.approval_process.expedited",
		"itgc.emergency_changes.documentation.post_implementation",
		"itgc.emergency_changes.review_process.timely",
		"itgc.emergency_changes.permanent_fix.implemented",
	],
	"change_documentation_complete": [
		"itgc.change_documentation.requirements.documented",
		"itgc.change_documentation.design_specifications.complete",
		"itgc.change_documentation.test_results.recorded",
		"itgc.change_documentation.implementation_guide.available",
	],
	"system_monitoring_effective": [
		"itgc.system_monitoring.availability_monitoring.real_time",
		"itgc.system_monitoring.performance_monitoring.continuous",
		"itgc.system_monitoring.error_monitoring.automated",
		"itgc.system_monitoring.security_monitoring.comprehensive",
		"itgc.system_monitoring.alerting.immediate",
	],
	"incident_management_robust": [
		"itgc.incident_management.incident_detection.automated",
		"itgc.incident_management.response_procedures.documented",
		"itgc.incident_management.escalation_process.defined",
		"itgc.incident_management.resolution_tracking.maintained",
		"itgc.incident_management.post_incident_review.conducted",
	],
	"capacity_management_adequate": [
		"itgc.capacity_management.capacity_planning.annual",
		"itgc.capacity_management.resource_monitoring.continuous",
		"itgc.capacity_management.growth_projections.documented",
		"itgc.capacity_management.scalability_testing.periodic",
	],
	"performance_monitoring_continuous": [
		"itgc.performance_monitoring.response_time.monitored",
		"itgc.performance_monitoring.throughput.measured",
		"itgc.performance_monitoring.resource_utilization.tracked",
		"itgc.performance_monitoring.trend_analysis.performed",
	],
	"sdlc_process_defined": [
		"itgc.sdlc.methodology.documented",
		"itgc.sdlc.phases.clearly_defined",
		"itgc.sdlc.deliverables.specified",
		"itgc.sdlc.quality_gates.implemented",
		"itgc.sdlc.approval_checkpoints.required",
	],
	"security_requirements_integrated": [
		"itgc.security_requirements.threat_modeling.conducted",
		"itgc.security_requirements.security_controls.designed",
		"itgc.security_requirements.vulnerability_assessment.performed",
		"itgc.security_requirements.penetration_testing.completed",
	],
	"code_review_mandatory": [
		"itgc.code_review.peer_review.required",
		"itgc.code_review.security_review.mandatory",
		"itgc.code_review.automated_scanning.performed",
		"itgc.code_review.findings_remediation.tracked",
	],
	"deployment_process_controlled": [
		"itgc.deployment.automated_deployment.implemented",
		"itgc.deployment.environment_consistency.maintained",
		"itgc.deployment.rollback_capability.tested",
		"itgc.deployment.deployment_verification.automated",
	],
	"physical_security_adequate": [
		"itgc.physical_security.access_controls.multi_factor",
		"itgc.physical_security.visitor_management.controlled",
		"itgc.physical_security.surveillance.comprehensive",
		"itgc.physical_security.access_logging.complete",
		"itgc.physical_security.security_guards.present",
	],
	"environmental_controls_effective": [
		"itgc.environmental.temperature_control.monitored",
		"itgc.environmental.humidity_control.maintained",
		"itgc.environmental.fire_suppression.tested",
		"itgc.environmental.water_detection.implemented",
		"itgc.environmental.air_quality.monitored",
	],
	"power_systems_redundant": [
		"itgc.power_systems.ups_systems.redundant",
		"itgc.power_systems.backup_generators.tested",
		"itgc.power_systems.power_monitoring.continuous",
		"itgc.power_systems.load_balancing.implemented",
	],
	"network_infrastructure_secure": [
		"itgc.network.network_segmentation.implemented",
		"itgc.network.firewall_management.controlled",
		"itgc.network.intrusion_detection.deployed",
		"itgc.network.network_monitoring.comprehensive",
	],
	"backup_procedures_comprehensive": [
		"itgc.backup.backup_frequency.appropriate",
		"itgc.backup.backup_verification.automated",
		"itgc.backup.offsite_storage.implemented",
		"itgc.backup.backup_encryption.enforced",
		"itgc.backup.retention_policy.documented",
	],
	"recovery_procedures_tested": [
		"itgc.recovery.recovery_testing.quarterly",
		"itgc.recovery.recovery_time_objectives.met",
		"itgc.recovery.recovery_point_objectives.achieved",
		"itgc.recovery.recovery_documentation.current",
	],
	"disaster_recovery_planned": [
		"itgc.disaster_recovery.dr_plan.documented",
		"itgc.disaster_recovery.dr_site.configured",
		"itgc.disaster_recovery.dr_testing.annual",
		"itgc.disaster_recovery.communication_plan.defined",
	],
	"business_continuity_ensured": [
		"itgc.business_continuity.bcp_plan.documented",
		"itgc.business_continuity.impact_analysis.current",
		"itgc.business_continuity.alternative_processes.defined",
		"itgc.business_continuity.staff_training.conducted",
	],
	"financial_system_access_controlled": [
		"financial_systems.access_controls.role_based",
		"financial_systems.privileged_access.restricted",
		"financial_systems.access_monitoring.real_time",
		"financial_systems.access_certification.quarterly",
	],
	"financial_data_integrity_maintained": [
		"financial_data.data_validation.comprehensive",
		"financial_data.data_reconciliation.automated",
		"financial_data.data_archival.secure",
		"financial_data.data_retention.compliant",
	],
	"financial_processing_controls_effective": [
		"financial_processing.transaction_processing.controlled",
		"financial_processing.batch_processing.monitored",
		"financial_processing.exception_handling.documented",
		"financial_processing.processing_completeness.verified",
	],
	"financial_reporting_systems_secure": [
		"financial_reporting.report_generation.controlled",
		"financial_reporting.report_distribution.authorized",
		"financial_reporting.report_archival.secure",
		"financial_reporting.report_integrity.maintained",
	],
	"_access_control_attested": [
		"itgc.access_controls.implemented",
	],
	"_change_management_attested": [
		"itgc.change_management.controlled",
	],
	"_computer_operations_attested": [
		"itgc.computer_operations.monitored",
	],
	"_system_development_attested": [
		"itgc.system_development.secure",
	],
	"_data_center_attested": [
		"itgc.data_center_operations.controlled",
	],
	"_backup_recovery_attested": [
		"itgc.backup_recovery.tested",
	],
}

_all_true(paths) if {
	every path in paths {
		_fact(path) == true
	}
}

# Named evidence problems for the facts of the checks that do not pass.
_evidence_problems(checks) := [problem |
	some check in checks
	check.check != true
	some path in _facts[check.rule]
	problem := _problem(path)
]

evidence_problems := _evidence_problems(_all_checks)

# ---------------------------------------------------------------------------
# Evidence source. Facts are posted as the input document, under input.sox, like every other module in
# this library. A caller that still loads them as the data document data.sox is served only when the
# input has no "sox" key at all. The two are never merged: once input.sox is posted (even as null, or
# with one fact), nothing is read from data.sox, so loaded data cannot override or fill in posted input.
# ---------------------------------------------------------------------------

default _input_has_sox := false

_input_has_sox if {
	is_object(input)
	"sox" in object.keys(input)
}

# The data.sox areas this module reads, each by a ground reference (data.sox also holds the sox packages,
# so it is never read whole). An area that is not loaded has no entry.
_data_area["itgc.logical_access"] := data.sox.itgc.logical_access

_data_area["itgc.privileged_access"] := data.sox.itgc.privileged_access

_data_area["itgc.access_reviews"] := data.sox.itgc.access_reviews

_data_area["itgc.segregation_of_duties"] := data.sox.itgc.segregation_of_duties

_data_area["itgc.change_approval"] := data.sox.itgc.change_approval

_data_area["itgc.change_testing"] := data.sox.itgc.change_testing

_data_area["itgc.emergency_changes"] := data.sox.itgc.emergency_changes

_data_area["itgc.change_documentation"] := data.sox.itgc.change_documentation

_data_area["itgc.system_monitoring"] := data.sox.itgc.system_monitoring

_data_area["itgc.incident_management"] := data.sox.itgc.incident_management

_data_area["itgc.capacity_management"] := data.sox.itgc.capacity_management

_data_area["itgc.performance_monitoring"] := data.sox.itgc.performance_monitoring

_data_area["itgc.sdlc"] := data.sox.itgc.sdlc

_data_area["itgc.security_requirements"] := data.sox.itgc.security_requirements

_data_area["itgc.code_review"] := data.sox.itgc.code_review

_data_area["itgc.deployment"] := data.sox.itgc.deployment

_data_area["itgc.physical_security"] := data.sox.itgc.physical_security

_data_area["itgc.environmental"] := data.sox.itgc.environmental

_data_area["itgc.power_systems"] := data.sox.itgc.power_systems

_data_area["itgc.network"] := data.sox.itgc.network

_data_area["itgc.backup"] := data.sox.itgc.backup

_data_area["itgc.recovery"] := data.sox.itgc.recovery

_data_area["itgc.disaster_recovery"] := data.sox.itgc.disaster_recovery

_data_area["itgc.business_continuity"] := data.sox.itgc.business_continuity

_data_area["financial_systems"] := data.sox.financial_systems

_data_area["financial_data"] := data.sox.financial_data

_data_area["financial_processing"] := data.sox.financial_processing

_data_area["financial_reporting"] := data.sox.financial_reporting

_data_area["itgc.access_controls"] := data.sox.itgc.access_controls

_data_area["itgc.change_management"] := data.sox.itgc.change_management

_data_area["itgc.computer_operations"] := data.sox.itgc.computer_operations

_data_area["itgc.system_development"] := data.sox.itgc.system_development

_data_area["itgc.data_center_operations"] := data.sox.itgc.data_center_operations

_data_area["itgc.backup_recovery"] := data.sox.itgc.backup_recovery

default _data_sox_loaded := false

_data_sox_loaded if count(_data_area) > 0

_nest([area], value) := {area: value}

_nest([package_name, area], value) := {package_name: {area: value}}

_data_sox := object.union_n([_nest(split(key, "."), value) | some key, value in _data_area])

# "input", "data" or "none" (nothing posted and nothing loaded).
evidence_source := "input" if {
	_input_has_sox
} else := "data" if {
	_data_sox_loaded
} else := "none"

# True when data.sox is loaded and was not read because input.sox was posted.
default data_sox_ignored := false

data_sox_ignored if {
	_input_has_sox
	_data_sox_loaded
}

# An input.sox that is not an object (null, a string) reads as empty: every fact is missing evidence.
_sox := input.sox if {
	_input_has_sox
	is_object(input.sox)
} else := {} if {
	_input_has_sox
} else := _data_sox

_source_document := "data" if {
	evidence_source == "data"
} else := "input"

# A fact by its dotted path below sox; null when it is absent or its parent is not an object.
_fact(path) := object.get(_sox, split(path, "."), null)

# The fact's full name in the document it was read from, for findings.
_ref(path) := sprintf("%s.sox.%s", [_source_document, path])

# Only the booleans are evidence. Anything else is named as an evidence problem.
_problem(path) := sprintf("evidence missing: %s not collected", [_ref(path)]) if {
	_fact(path) == null
}

_problem(path) := sprintf("%s is not a boolean (got %s)", [_ref(path), type_name(_fact(path))]) if {
	_fact(path) != null
	not is_boolean(_fact(path))
}
