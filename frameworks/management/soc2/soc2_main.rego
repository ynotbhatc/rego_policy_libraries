# SOC 2 - AICPA Trust Services Criteria: criterion-level report for 12 of the 33 common criteria
# (CC1.2, CC1.4, CC3.2, CC6.1, CC6.2, CC6.3, CC6.6, CC7.2, CC7.4, CC8.1, CC9.1, CC9.2), plus
# category-level verdicts for the optional categories in scope. See "CRITERION-LEVEL REPORT".

# METADATA
# title: "SOC 2 Trust Services Criteria - 12 common criteria scored by id, optional categories category-level"
# custom:
#   class: compliance
#   framework: soc2
#   source: aicpa
#   domains: [assurance]
#   coverage:
#     checks: 4
#     cited: 1
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package soc2.main

import rego.v1

import data.soc2.availability.system_availability
import data.soc2.confidentiality.data_confidentiality
import data.soc2.privacy.data_privacy
import data.soc2.processing_integrity.data_processing
import data.soc2.security.access_controls

# Infrastructure components
import data.soc2.infrastructure.applications_services
import data.soc2.infrastructure.network as network_infrastructure
import data.soc2.infrastructure.security as security_infrastructure
import data.soc2.infrastructure.storage as storage_infrastructure
import data.soc2.infrastructure.systems as systems_infrastructure

# =================================================================
# SOC 2 TRUST SERVICE CRITERIA AGGREGATION
# =================================================================

# Security (Common Criteria) - Required for all SOC 2 reports
default security_compliant := false

security_compliant if {
	access_controls.overall_security_compliant
}

# Availability - Optional criteria
default availability_compliant := false

availability_compliant if {
	system_availability.overall_availability_compliant
}

# Processing Integrity - Optional criteria
default processing_integrity_compliant := false

processing_integrity_compliant if {
	data_processing.overall_processing_integrity_compliant
}

# Confidentiality - Optional criteria
default confidentiality_compliant := false

confidentiality_compliant if {
	data_confidentiality.overall_confidentiality_compliant
}

# Privacy - Optional criteria
default privacy_compliant := false

privacy_compliant if {
	data_privacy.overall_privacy_compliant
}

# =================================================================
# INFRASTRUCTURE COMPLIANCE ASSESSMENT
# =================================================================

# Network infrastructure compliance
default network_infrastructure_compliant := false

network_infrastructure_compliant if {
	network_infrastructure.overall_network_infrastructure_compliant
}

# Security infrastructure compliance
default security_infrastructure_compliant := false

security_infrastructure_compliant if {
	security_infrastructure.overall_security_infrastructure_compliant
}

# Systems infrastructure compliance
default systems_infrastructure_compliant := false

systems_infrastructure_compliant if {
	systems_infrastructure.overall_systems_infrastructure_compliant
}

# Storage infrastructure compliance
default storage_infrastructure_compliant := false

storage_infrastructure_compliant if {
	storage_infrastructure.overall_storage_infrastructure_compliant
}

# Applications and services compliance
default applications_services_compliant := false

applications_services_compliant if {
	applications_services.overall_applications_services_compliant
}

# =================================================================
# COMPREHENSIVE SOC 2 COMPLIANCE ASSESSMENT
# =================================================================

# SOC 2 Type I - Point-in-time assessment
soc2_type_i_compliant if {
	security_compliant

	# Additional criteria based on service commitments
	count([criteria |
		criteria := [availability_compliant, processing_integrity_compliant, confidentiality_compliant, privacy_compliant][_]
		criteria == true
	]) >= 1
}

# SOC 2 Type II - Operating effectiveness over time
soc2_type_ii_compliant if {
	soc2_type_i_compliant
	operating_effectiveness_demonstrated
}

# Operating effectiveness criteria
operating_effectiveness_demonstrated if {
	input.soc2.operating_effectiveness.testing_period_months >= 12
	input.soc2.operating_effectiveness.continuous_monitoring == true
	input.soc2.operating_effectiveness.exception_reporting == true
	input.soc2.operating_effectiveness.management_response.documented == true
}

# =================================================================
# SOC 2 SCOPE AND SERVICE COMMITMENTS
# =================================================================

# Service commitments and system requirements are defined
default service_commitments_defined := false

service_commitments_defined if {
	input.soc2.service_commitments.security.defined == true
	input.soc2.service_commitments.suitability_of_design == true
	input.soc2.service_commitments.operating_effectiveness == true
}

# System boundaries are properly defined
default system_boundaries_defined := false

system_boundaries_defined if {
	input.soc2.system_boundaries.infrastructure.documented == true
	input.soc2.system_boundaries.software.documented == true
	input.soc2.system_boundaries.people.documented == true
	input.soc2.system_boundaries.procedures.documented == true
	input.soc2.system_boundaries.data.documented == true
}

# =================================================================
# RISK ASSESSMENT AND MANAGEMENT
# =================================================================

# Risk assessment process is established
default risk_assessment_established := false

risk_assessment_established if {
	input.soc2.risk_management.risk_assessment.periodic == true
	input.soc2.risk_management.risk_assessment.methodology.defined == true
	input.soc2.risk_management.risk_identification.comprehensive == true
	input.soc2.risk_management.risk_response.documented == true
}

# Risk monitoring and reporting
default risk_monitoring_active := false

risk_monitoring_active if {
	input.soc2.risk_management.monitoring.continuous == true
	input.soc2.risk_management.reporting.regular == true
	input.soc2.risk_management.escalation.procedures.defined == true
}

# =================================================================
# CONTROL ENVIRONMENT
# =================================================================

# Management oversight and tone at the top
default management_oversight := false

management_oversight if {
	input.soc2.control_environment.governance.board_oversight == true
	input.soc2.control_environment.governance.management_philosophy == true
	input.soc2.control_environment.integrity.code_of_conduct == true
	input.soc2.control_environment.competence.defined_roles == true
}

# Human resources controls
default hr_controls_effective := false

hr_controls_effective if {
	input.soc2.human_resources.background_checks == true
	input.soc2.human_resources.training_programs == true
	input.soc2.human_resources.performance_evaluations == true
	input.soc2.human_resources.disciplinary_procedures == true
}

# =================================================================
# VENDOR AND SUBSERVICE ORGANIZATION MANAGEMENT
# =================================================================

# Vendor management program
default vendor_management_program := false

vendor_management_program if {
	input.soc2.vendor_management.due_diligence.performed == true
	input.soc2.vendor_management.contracts.security_requirements == true
	input.soc2.vendor_management.monitoring.ongoing == true
	input.soc2.vendor_management.termination.procedures.defined == true
}

# Subservice organization oversight
# No subservice organizations: pass. Otherwise every listed organization must carry a current SOC report.
# The key must be present (a missing list is not evidence of "none").
default subservice_organization_oversight := false

subservice_organization_oversight if {
	orgs := input.soc2.subservice_organizations
	count([org | some org in orgs; not _subservice_org_overseen(org)]) == 0
}

_subservice_org_overseen(org) if org.soc_report.current == true

# =================================================================
# CHANGE MANAGEMENT
# =================================================================

# Change management process
default change_management_process := false

change_management_process if {
	input.soc2.change_management.process.documented == true
	input.soc2.change_management.approval.required == true
	input.soc2.change_management.testing.required == true
	input.soc2.change_management.rollback.procedures.defined == true
}

# Configuration management
default configuration_management := false

configuration_management if {
	input.soc2.configuration_management.baseline.established == true
	input.soc2.configuration_management.version_control == true
	input.soc2.configuration_management.unauthorized_changes.detection == true
}

# =================================================================
# INCIDENT RESPONSE AND BUSINESS CONTINUITY
# =================================================================

# Incident response program
default incident_response_program := false

incident_response_program if {
	input.soc2.incident_response.program.established == true
	input.soc2.incident_response.team.defined == true
	input.soc2.incident_response.procedures.documented == true
	input.soc2.incident_response.testing.regular == true
}

# Business continuity planning
default business_continuity_planning := false

business_continuity_planning if {
	input.soc2.business_continuity.plan.documented == true
	input.soc2.business_continuity.testing.annual == true
	input.soc2.business_continuity.recovery_objectives.defined == true
	input.soc2.business_continuity.communication.plan.defined == true
}

# =================================================================
# MONITORING AND LOGGING
# =================================================================

# System monitoring
default system_monitoring_comprehensive := false

system_monitoring_comprehensive if {
	input.soc2.monitoring.infrastructure.comprehensive == true
	input.soc2.monitoring.applications.comprehensive == true
	input.soc2.monitoring.security_events.real_time == true
	input.soc2.monitoring.performance.continuous == true
}

# Log management
default log_management_effective := false

log_management_effective if {
	input.soc2.logging.centralized == true
	input.soc2.logging.integrity_protection == true
	input.soc2.logging.retention.adequate == true
	input.soc2.logging.review.regular == true
}

# =================================================================
# OVERALL SOC 2 ASSESSMENT
# =================================================================

# Core SOC 2 requirements
core_soc2_requirements_met if {
	service_commitments_defined
	system_boundaries_defined
	risk_assessment_established
	risk_monitoring_active
	management_oversight
	hr_controls_effective
}

# Operational controls
operational_controls_effective if {
	vendor_management_program
	subservice_organization_oversight
	change_management_process
	configuration_management
	incident_response_program
	business_continuity_planning
}

# Monitoring and oversight
monitoring_oversight_effective if {
	system_monitoring_comprehensive
	log_management_effective
}

# Infrastructure compliance aggregate
infrastructure_compliant if {
	network_infrastructure_compliant
	security_infrastructure_compliant
	systems_infrastructure_compliant
	storage_infrastructure_compliant
	applications_services_compliant
}

# Overall SOC 2 compliance
default overall_soc2_compliant := false

overall_soc2_compliant if {
	security_compliant
	core_soc2_requirements_met
	operational_controls_effective
	monitoring_oversight_effective
	infrastructure_compliant
}

# =================================================================
# SOC 2 COMPLIANCE SCORING
# =================================================================

# Individual trust service criteria scores
trust_service_criteria_scores := scores if {
	scores := {
		"security": access_controls.security_score,
		"availability": system_availability.availability_score,
		"processing_integrity": data_processing.processing_integrity_score,
		"confidentiality": data_confidentiality.confidentiality_score,
		"privacy": data_privacy.privacy_score,
	}
}

# Infrastructure component scores
infrastructure_scores := scores if {
	scores := {
		"network": network_infrastructure.network_infrastructure_score,
		"security": security_infrastructure.security_infrastructure_score,
		"systems": systems_infrastructure.systems_infrastructure_score,
		"storage": storage_infrastructure.storage_infrastructure_score,
		"applications_services": applications_services.applications_services_score,
	}
}

# Overall SOC 2 compliance score
soc2_compliance_score := score if {
	# Weight security more heavily as it's required
	security_weight := 0.4
	other_criteria_weight := 0.15 # Each of the 4 optional criteria

	security_score := access_controls.security_score * security_weight
	availability_score := system_availability.availability_score * other_criteria_weight
	processing_integrity_score := data_processing.processing_integrity_score * other_criteria_weight
	confidentiality_score := data_confidentiality.confidentiality_score * other_criteria_weight
	privacy_score := data_privacy.privacy_score * other_criteria_weight

	score := (((security_score + availability_score) + processing_integrity_score) + confidentiality_score) + privacy_score
}

# =================================================================
# DETAILED SOC 2 FINDINGS
# =================================================================

soc2_detailed_findings := findings if {
	findings := {
		"trust_service_criteria": {
			"security": access_controls.security_findings,
			"availability": system_availability.availability_findings,
			"processing_integrity": data_processing.processing_integrity_findings,
			"confidentiality": data_confidentiality.confidentiality_findings,
			"privacy": data_privacy.privacy_findings,
		},
		"compliance_status": {
			"security_compliant": security_compliant,
			"availability_compliant": availability_compliant,
			"processing_integrity_compliant": processing_integrity_compliant,
			"confidentiality_compliant": confidentiality_compliant,
			"privacy_compliant": privacy_compliant,
			"soc2_type_i_compliant": soc2_type_i_compliant,
			"soc2_type_ii_compliant": soc2_type_ii_compliant,
			"overall_soc2_compliant": overall_soc2_compliant,
		},
		"scores": {
			"individual_criteria": trust_service_criteria_scores,
			"infrastructure_components": infrastructure_scores,
			"overall_compliance": soc2_compliance_score,
		},
		"operational_effectiveness": {
			"core_requirements_met": core_soc2_requirements_met,
			"operational_controls_effective": operational_controls_effective,
			"monitoring_oversight_effective": monitoring_oversight_effective,
		},
		"infrastructure": {
			"network": network_infrastructure.network_infrastructure_findings,
			"security": security_infrastructure.security_infrastructure_findings,
			"systems": systems_infrastructure.systems_infrastructure_findings,
			"storage": storage_infrastructure.storage_infrastructure_findings,
			"applications_services": applications_services.applications_services_findings,
		},
	}
}

# =================================================================
# CRITERION-LEVEL REPORT (framework-key entrypoint)
# =================================================================
#
# Source: AICPA, TSP section 100, 2017 Trust Services Criteria for Security,
# Availability, Processing Integrity, Confidentiality, and Privacy (points of
# focus revised 2022; the criteria themselves were not changed). The criteria
# are 33 common criteria (CC1.1-CC9.2), A1.1-A1.3, C1.1-C1.2, PI1.1-PI1.5 and
# P1.1-P8.1 (61 in all). No criterion text is reproduced here.
#
# What is scored: the common criteria below, each decided by the checks mapped
# to it (every check must pass). total_controls = the criteria scored; a
# criterion fails once however many of its checks fail.
#   CC1.2 board oversight            management_oversight
#   CC1.4 competence                 hr_controls_effective
#   CC3.2 risk identification        risk_assessment_established, risk_monitoring_active
#   CC6.1 logical access security    security: mfa_for_privileged_access, shared_accounts_managed,
#                                    network_segmentation_implemented, database_access_controlled
#   CC6.2 registration and review    security: user_lifecycle_managed, access_rights_reviewed
#   CC6.3 role-based authorization   security: user_access_properly_restricted
#   CC6.6 boundary / remote access   security: remote_access_secured
#   CC7.2 monitoring for anomalies   security: system_access_monitored, system_monitoring_comprehensive,
#                                    log_management_effective
#   CC7.4 incident response          incident_response_program
#   CC8.1 change management          change_management_process, configuration_management
#   CC9.1 business disruption        business_continuity_planning
#   CC9.2 vendors and partners       vendor_management_program, subservice_organization_oversight
# The other 21 common criteria have no check and are not claimed.
#
# Not scored by criterion: the four optional categories (availability,
# confidentiality, processing integrity, privacy). Their modules hard-code
# parameter values the criteria do not fix and their headings do not follow
# the criterion numbering, so they are reported as category-level verdicts:
# each category the entity puts in scope (input.soc2.categories_in_scope) must
# pass, and a missing scope list is a finding (all four are then assessed).
# The infrastructure modules and the OpenShift platform checks decide no
# criterion and are reported under `advisory`.
# The system description inputs (service commitments, system boundaries) are
# description-criteria prerequisites, not trust services criteria: they block
# compliance when missing but are not counted as criteria.

criteria_checks := {
	"CC1.2": {"management_oversight": management_oversight},
	"CC1.4": {"hr_controls_effective": hr_controls_effective},
	"CC3.2": {"risk_assessment_established": risk_assessment_established, "risk_monitoring_active": risk_monitoring_active},
	"CC6.1": {
		"security.mfa_for_privileged_access": access_controls.mfa_for_privileged_access,
		"security.shared_accounts_managed": access_controls.shared_accounts_managed,
		"security.network_segmentation_implemented": access_controls.network_segmentation_implemented,
		"security.database_access_controlled": access_controls.database_access_controlled,
	},
	"CC6.2": {
		"security.user_lifecycle_managed": access_controls.user_lifecycle_managed,
		"security.access_rights_reviewed": access_controls.access_rights_reviewed,
	},
	"CC6.3": {"security.user_access_properly_restricted": access_controls.user_access_properly_restricted},
	"CC6.6": {"security.remote_access_secured": access_controls.remote_access_secured},
	"CC7.2": {
		"security.system_access_monitored": access_controls.system_access_monitored,
		"system_monitoring_comprehensive": system_monitoring_comprehensive,
		"log_management_effective": log_management_effective,
	},
	"CC7.4": {"incident_response_program": incident_response_program},
	"CC8.1": {"change_management_process": change_management_process, "configuration_management": configuration_management},
	"CC9.1": {"business_continuity_planning": business_continuity_planning},
	"CC9.2": {"vendor_management_program": vendor_management_program, "subservice_organization_oversight": subservice_organization_oversight},
}

_failed_checks(c) := sort([k | some k, ok in criteria_checks[c]; ok != true])

failed_criteria := {c | some c, _ in criteria_checks; count(_failed_checks(c)) > 0}

criteria_status[c] := {"satisfied": count(_failed_checks(c)) == 0, "checks": checks, "failed_checks": _failed_checks(c)} if {
	some c, checks in criteria_checks
}

# Findings a check emits about missing evidence, by criterion prefix ("CC6.6: ...").
_evidence_for(c) := sort([m | some m in access_controls.evidence_findings; startswith(m, sprintf("%v:", [c]))])

criteria_findings contains msg if {
	some c in failed_criteria
	some k in _failed_checks(c)
	msg := sprintf("SOC 2 %v: check %v not satisfied", [c, k])
}

criteria_findings contains msg if {
	some c in failed_criteria
	some m in _evidence_for(c)
	msg := sprintf("SOC 2 %v", [m])
}

# --- optional categories (category-level, not scored by criterion) ---

_optional_categories := {"availability", "confidentiality", "processing_integrity", "privacy"}

_scope_list := l if {
	l := input.soc2.categories_in_scope
	is_array(l)
}

categories_in_scope := {c | some c in _scope_list; c in _optional_categories} if _scope_list

else := _optional_categories

_category_ok("availability") if availability_compliant == true
_category_ok("confidentiality") if confidentiality_compliant == true
_category_ok("processing_integrity") if processing_integrity_compliant == true
_category_ok("privacy") if privacy_compliant == true

prerequisite_findings contains "SOC 2 scope: evidence missing - input.soc2.categories_in_scope not supplied (an array naming the optional categories in the entity's report); all four optional categories are assessed" if {
	not _scope_list
}

prerequisite_findings contains msg if {
	some c in _scope_list
	not c in _optional_categories
	msg := sprintf("SOC 2 scope: unknown category %v - the optional categories are availability, confidentiality, processing_integrity, privacy (security is always in scope)", [c])
}

prerequisite_findings contains msg if {
	some c in categories_in_scope
	not _category_ok(c)
	msg := sprintf("SOC 2 %v (category in scope, category-level verdict, not scored by criterion): the %v module did not pass", [c, c])
}

prerequisite_findings contains "SOC 2 description prerequisite: service commitments are not shown defined (input.soc2.service_commitments)" if {
	not service_commitments_defined
}

prerequisite_findings contains "SOC 2 description prerequisite: system boundaries are not shown documented (input.soc2.system_boundaries)" if {
	not system_boundaries_defined
}

_violations := array.concat(sort(prerequisite_findings), sort(criteria_findings))

default _soc2_report_compliant := false

_soc2_report_compliant if {
	count(failed_criteria) == 0
	count(prerequisite_findings) == 0
}

advisory := {
	"scoring": false,
	"openshift_security": access_controls.openshift_security_compliant,
	"platform_evidence_findings": sort([m | some m in access_controls.evidence_findings; startswith(m, "platform:")]),
	"infrastructure": {
		"network": network_infrastructure_compliant,
		"security": security_infrastructure_compliant,
		"systems": systems_infrastructure_compliant,
		"storage": storage_infrastructure_compliant,
		"applications_services": applications_services_compliant,
	},
}

default compliance_report := {
	"framework_key": "soc2",
	"compliant": false,
	"fail_closed": true,
	"violations": [{"control": "FAIL-CLOSED", "title": "no report produced for soc2; this is not a passing result"}],
	"violation_count": 1,
	"failed_controls": 1,
	"total_controls": 1,
}

compliance_report := {
	"framework_key": "soc2",
	"standard": "SOC 2 - AICPA Trust Services Criteria (TSP section 100, 2017, points of focus revised 2022)",
	"scope_note": "Scores 12 of the 33 common criteria (listed in criteria); the optional categories are category-level verdicts, not scored by criterion",
	"compliant": _soc2_report_compliant,
	"total_controls": count(criteria_checks),
	"failed_controls": count(failed_criteria),
	"criteria": criteria_status,
	"failed_criteria": sort(failed_criteria),
	"categories_in_scope": sort(categories_in_scope),
	"trust_services": {
		"security": security_compliant == true,
		"availability": availability_compliant == true,
		"confidentiality": confidentiality_compliant == true,
		"processing_integrity": processing_integrity_compliant == true,
		"privacy": privacy_compliant == true,
	},
	"advisory": advisory,
	"violations": _violations,
	"violation_count": count(_violations),
}
