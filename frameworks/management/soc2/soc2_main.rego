# SOC 2 - AICPA Trust Services Criteria: per-criterion results for all 33 common criteria (CC1.1-CC9.2):
# 10 decided from evidence (CC6.1, CC6.2, CC6.3, CC6.5, CC6.6, CC6.7, CC6.8, CC7.1, CC7.2, CC8.1) and 23 by
# signed attestation, plus up to 16 criteria of the optional categories in scope (A1.1-A1.3, C1.1-C1.2,
# PI1.2-PI1.3, P3.1, P3.2, P4.1, P4.2, P5.1, P5.2, P6.1, P6.6, P7.1). See "CRITERION-LEVEL REPORT".

# METADATA
# title: "SOC 2 Trust Services Criteria - all 33 common criteria and up to 16 optional-category criteria, per-criterion results"
# custom:
#   class: compliance
#   framework: soc2
#   source: aicpa
#   domains: [assurance]
#   coverage:
#     checks: 56
#     cited: 33
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package soc2.main

import rego.v1

import data.soc2.availability.system_availability
import data.soc2.confidentiality.data_confidentiality
import data.soc2.privacy.data_privacy
import data.soc2.processing_integrity.data_processing
import data.soc2.security.access_controls

import data.soc2.criteria as cc

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
	is_number(input.soc2.operating_effectiveness.testing_period_months)
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
# What is evaluated: every one of the 33 common criteria, and the mapped criteria of each optional
# category in scope, by data.soc2.criteria (frameworks/management/soc2/criteria/soc2_criteria.rego), which
# lists for each criterion its basis, the input paths it reads and the test each must meet.
#   evidence (10)     CC6.1 CC6.2 CC6.3 CC6.5 CC6.6 CC6.7 CC6.8 CC7.1 CC7.2 CC8.1
#   attestation (23)  CC1.1-CC1.5 CC2.1-CC2.3 CC3.1-CC3.4 CC4.1-CC4.2 CC5.1-CC5.3 CC6.4 CC7.3 CC7.4 CC7.5
#                     CC9.1 CC9.2, met by input.soc2.attestations["<id>"] = {attested: true, by, date};
#                     CC1.2, CC1.4, CC3.2, CC7.4, CC9.1 and CC9.2 also still need the records read before
#                     (control_environment, human_resources, risk_management, incident_response,
#                     business_continuity, vendor_management, subservice_organizations)
# control_results gives one row per criterion: status pass | fail | evidence_missing | not_attested, the
# vocabulary of nist_800_53.main and tisax.main. Missing evidence or a missing attestation is evidence_missing
# and an unsigned attestation is not_attested; neither is ever a pass. total_controls = rows; failed_controls = rows that did not pass; compliant = every row passed, the
# description prerequisites hold and the input carries no unreadable attestation.
#
# Optional categories: their criteria are evaluated for each category the entity puts in scope
# (input.soc2.categories_in_scope); a missing scope list is a finding and all four are then assessed. The
# category modules' own verdicts hard-code values the criteria do not fix and decide nothing
# (advisory.categories). The infrastructure modules and the OpenShift platform checks decide no criterion
# and are reported under `advisory`. The system description inputs (service commitments, system
# boundaries) are description-criteria prerequisites, not trust services criteria: they block compliance
# when missing but are not counted as criteria.
#
# The mapped checks below (criteria_checks, reported as compliance_report.criteria) are the earlier
# check-per-criterion view and are kept for readers of that field; they decide nothing.
_common_criteria_checks := {
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

# --- optional categories: criteria scored when the category is in scope ---
#
# Each criterion is decided by checks written here against the category inputs,
# holding no value the criteria do not fix: where a period or limit is needed it
# is the entity's commitment (input.soc2.commitments.<key>) compared with the
# observed value, both guarded with is_number. The category modules' own checks
# (which hard-code values such as 99.9 % uptime, 80 % CPU warnings, daily
# backups, 2000 ms, 24-hour reconciliation, 72-hour breach notice, and
# mechanisms such as digital signatures, DLP or a four-tier classification) are
# not scored: they appear under advisory.categories.
#   A1.1 capacity managed             capacity monitoring and forecasting, infrastructure monitoring with alerts
#   A1.2 backup / recovery infra      automated backups, off-site copies, retention >= commitment
#   A1.3 recovery plan tested         recovery test interval <= commitment
#   C1.1 confidential info identified classification defines confidential information; access by classification
#   C1.2 confidential info disposed   documented disposal procedure with verified completion
#   PI1.2 inputs                      input validation (type, range, format)
#   PI1.3 processing                  authorised processing with audit trail; error handling and recovery
#   P3.1 collection                   documented collection policy, purpose, minimisation
#   P3.2 explicit consent             explicit consent required and tracked
#   P4.1 use limited                  purpose limitation, compatible use only
#   P4.2 retention                    documented retention policy and schedules
#   P5.1 access                       data-subject access requests supported
#   P5.2 correction                   rectification supported
#   P6.1 disclosure to third parties  documented agreements and due diligence
#   P6.6 breach notification          documented procedure; notice times <= commitments
#   P7.1 quality                      accuracy verification and correction procedures
# Not mapped (no check): PI1.1, PI1.4, PI1.5, P1.1, P2.1, P6.2-P6.5, P6.7, P8.1.

_commitment(key) := v if {
	v := input.soc2.commitments[key]
	is_number(v)
}

_observed(path) := v if {
	v := object.get(input, path, null)
	is_number(v)
}

default backup_recovery_infrastructure := false

backup_recovery_infrastructure if {
	input.backup.automated_backups.enabled == true
	input.backup.offsite_storage.enabled == true
	_observed(["backup", "retention", "days"]) >= _commitment("backup_retention_days")
}

default recovery_plan_tested := false

recovery_plan_tested if _observed(["backup", "recovery_testing", "frequency_days"]) <= _commitment("recovery_test_interval_days")

default capacity_managed := false

capacity_managed if {
	input.capacity_management.monitoring.enabled == true
	input.capacity_management.forecasting.enabled == true
	input.monitoring.infrastructure.enabled == true
	input.monitoring.alerts.configured == true
}

default confidential_information_identified := false

confidential_information_identified if {
	input.data_classification.system_defined == true
	input.data_classification.categories.confidential.defined == true
	input.data_classification.access_controls.role_based == true
	input.data_classification.access_controls.need_to_know == true
}

default confidential_information_disposed := false

confidential_information_disposed if {
	input.data_disposal.procedures.documented == true
	input.data_disposal.verification.completion_verified == true
}

default processing_inputs_controlled := false

processing_inputs_controlled if {
	input.data_processing.input_validation.enabled == true
	input.data_processing.input_validation.data_type_checking == true
	input.data_processing.input_validation.range_checking == true
	input.data_processing.input_validation.format_validation == true
}

default processing_controlled := false

processing_controlled if {
	input.data_processing.authorization.required == true
	input.data_processing.authorization.audit_trail == true
	input.data_processing.error_handling.logging.enabled == true
	input.data_processing.error_handling.recovery_procedures.documented == true
}

default pi_collection_consistent := false

pi_collection_consistent if {
	input.privacy.collection.policy_documented == true
	input.privacy.collection.purpose_limitation == true
	input.privacy.collection.data_minimization == true
}

default explicit_consent_obtained := false

explicit_consent_obtained if {
	input.privacy.consent.explicit_consent_required == true
	input.privacy.consent.consent_tracking.enabled == true
}

default pi_use_limited := false

pi_use_limited if {
	input.privacy.use.purpose_limitation == true
	input.privacy.use.compatible_use_only == true
}

default pi_retained_per_schedule := false

pi_retained_per_schedule if {
	input.privacy.retention.policies_documented == true
	input.privacy.retention.retention_schedules.defined == true
}

default pi_access_granted := false

pi_access_granted if input.privacy.data_subject_rights.access_request.supported == true

default pi_correction_supported := false

pi_correction_supported if input.privacy.data_subject_rights.rectification.supported == true

default pi_third_party_disclosure_controlled := false

pi_third_party_disclosure_controlled if {
	input.privacy.third_party_sharing.documented_agreements == true
	input.privacy.third_party_sharing.due_diligence_performed == true
}

default breach_notification_within_commitments := false

breach_notification_within_commitments if {
	input.privacy.breach_notification.procedures_documented == true
	_observed(["privacy", "breach_notification", "timeline_compliance", "authorities"]) <= _commitment("breach_notice_hours_authorities")
	_observed(["privacy", "breach_notification", "timeline_compliance", "individuals"]) <= _commitment("breach_notice_hours_individuals")
}

default pi_quality_maintained := false

pi_quality_maintained if {
	input.privacy.data_quality.accuracy_verification == true
	input.privacy.data_quality.correction_procedures == true
}

_optional_criteria_checks := {
	"availability": {
		"A1.1": {"capacity_managed": capacity_managed},
		"A1.2": {"backup_recovery_infrastructure": backup_recovery_infrastructure},
		"A1.3": {"recovery_plan_tested": recovery_plan_tested},
	},
	"confidentiality": {
		"C1.1": {"confidential_information_identified": confidential_information_identified},
		"C1.2": {"confidential_information_disposed": confidential_information_disposed},
	},
	"processing_integrity": {
		"PI1.2": {"processing_inputs_controlled": processing_inputs_controlled},
		"PI1.3": {"processing_controlled": processing_controlled},
	},
	"privacy": {
		"P3.1": {"pi_collection_consistent": pi_collection_consistent},
		"P3.2": {"explicit_consent_obtained": explicit_consent_obtained},
		"P4.1": {"pi_use_limited": pi_use_limited},
		"P4.2": {"pi_retained_per_schedule": pi_retained_per_schedule},
		"P5.1": {"pi_access_granted": pi_access_granted},
		"P5.2": {"pi_correction_supported": pi_correction_supported},
		"P6.1": {"pi_third_party_disclosure_controlled": pi_third_party_disclosure_controlled},
		"P6.6": {"breach_notification_within_commitments": breach_notification_within_commitments},
		"P7.1": {"pi_quality_maintained": pi_quality_maintained},
	},
}

_in_scope_criteria := {c: checks |
	some cat in categories_in_scope
	some c, checks in _optional_criteria_checks[cat]
}

criteria_checks := object.union(_common_criteria_checks, _in_scope_criteria)

# Evidence findings for the optional-category commitments (criterion id literal in each message).
category_evidence_findings contains "A1.2: evidence missing - input.soc2.commitments.backup_retention_days (the entity's stated value) not supplied or not a number" if not _commitment("backup_retention_days")

category_evidence_findings contains "A1.2: evidence missing - input.backup.retention.days not collected or not a number" if not _observed(["backup", "retention", "days"])

category_evidence_findings contains "A1.3: evidence missing - input.soc2.commitments.recovery_test_interval_days (the entity's stated value) not supplied or not a number" if not _commitment("recovery_test_interval_days")

category_evidence_findings contains "A1.3: evidence missing - input.backup.recovery_testing.frequency_days not collected or not a number" if not _observed(["backup", "recovery_testing", "frequency_days"])

category_evidence_findings contains "P6.6: evidence missing - input.soc2.commitments.breach_notice_hours_authorities (the entity's stated value) not supplied or not a number" if not _commitment("breach_notice_hours_authorities")

category_evidence_findings contains "P6.6: evidence missing - input.soc2.commitments.breach_notice_hours_individuals (the entity's stated value) not supplied or not a number" if not _commitment("breach_notice_hours_individuals")

category_evidence_findings contains "P6.6: evidence missing - input.privacy.breach_notification.timeline_compliance.authorities not collected or not a number" if not _observed(["privacy", "breach_notification", "timeline_compliance", "authorities"])

category_evidence_findings contains "P6.6: evidence missing - input.privacy.breach_notification.timeline_compliance.individuals not collected or not a number" if not _observed(["privacy", "breach_notification", "timeline_compliance", "individuals"])

_failed_checks(c) := sort([k | some k, ok in criteria_checks[c]; ok != true])

criteria_status[c] := {"satisfied": count(_failed_checks(c)) == 0, "checks": checks, "failed_checks": _failed_checks(c)} if {
	some c, checks in criteria_checks
}

# Per-criterion results (data.soc2.criteria): every common criterion, plus the mapped criteria of the
# optional categories in scope, in natural id order. criteria_status above keeps the earlier mapped checks
# for readers of compliance_report.criteria; it decides nothing. The decision is control_results.
_id_in_scope(id) if cc.criteria[id].category == "security"

_id_in_scope(id) if cc.criteria[id].category in categories_in_scope

_in_scope_ids := [id | some id in cc.order; _id_in_scope(id)]

control_results := [cc.result_of[id] | some id in _in_scope_ids]

control_result_counts := {s: count([r | some r in control_results; r.status == s]) | some s in ["pass", "fail", "evidence_missing", "not_attested"]}

basis_counts := {b: count([r | some r in control_results; r.basis == b]) | some b in ["evidence", "attestation"]}

failed_criteria := {id | some id in _in_scope_ids; cc.status_of[id] != "pass"}

# One finding per criterion part that is not met; the criterion id leads each message ("SOC 2 CC6.6: ...").
criteria_findings contains msg if {
	some id in _in_scope_ids
	some msg in cc.findings_of[id]
}

# --- scope of the optional categories ---

_optional_categories := {"availability", "confidentiality", "processing_integrity", "privacy"}

_scope_list := l if {
	l := input.soc2.categories_in_scope
	is_array(l)
}

categories_in_scope := {c | some c in _scope_list; c in _optional_categories} if _scope_list

else := _optional_categories

prerequisite_findings contains "SOC 2 scope: evidence missing - input.soc2.categories_in_scope not supplied (an array naming the optional categories in the entity's report); all four optional categories are assessed" if {
	not _scope_list
}

prerequisite_findings contains msg if {
	some c in _scope_list
	not c in _optional_categories
	msg := sprintf("SOC 2 scope: unknown category %v - the optional categories are availability, confidentiality, processing_integrity, privacy (security is always in scope)", [c])
}

prerequisite_findings contains "SOC 2 description prerequisite: service commitments are not shown defined (input.soc2.service_commitments)" if {
	not service_commitments_defined
}

prerequisite_findings contains "SOC 2 description prerequisite: system boundaries are not shown documented (input.soc2.system_boundaries)" if {
	not system_boundaries_defined
}

_violations := array.concat(sort(prerequisite_findings | cc.input_notes), sort(criteria_findings))

default _soc2_report_compliant := false

_soc2_report_compliant if {
	count(control_results) > 0
	count(failed_criteria) == 0
	count(prerequisite_findings) == 0
	count(cc.input_notes) == 0
}

advisory := {
	"scoring": false,
	"openshift_security": access_controls.openshift_security_compliant,
	"platform_evidence_findings": sort([m | some m in access_controls.evidence_findings; startswith(m, "platform:")]),
	"categories": {
		"note": "category-module verdicts; they hard-code values the criteria do not fix and decide no criterion",
		"availability": availability_compliant,
		"confidentiality": confidentiality_compliant,
		"processing_integrity": processing_integrity_compliant,
		"privacy": privacy_compliant,
	},
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
	"scope_note": "Evaluates all 33 common criteria (10 from evidence, 23 by signed attestation) plus the mapped criteria of the optional categories in scope; evidence_missing and not_attested are never a pass; category-module verdicts are advisory",
	"compliant": _soc2_report_compliant,
	"total_controls": count(control_results),
	"failed_controls": count(failed_criteria),
	"control_results": control_results,
	"control_result_counts": control_result_counts,
	"basis_counts": basis_counts,
	"coverage": {
		"common_criteria_total": 33,
		"common_criteria_evaluated": count([r | some r in control_results; r.category == "security"]),
		"optional_criteria_mapped": count([id | some id, c in cc.criteria; c.category != "security"]),
		"optional_criteria_not_mapped": cc.not_mapped,
	},
	"criteria": criteria_status,
	"criteria_note": "criteria lists the earlier mapped checks per criterion; they decide nothing, control_results does",
	"failed_criteria": [id | some id in _in_scope_ids; id in failed_criteria],
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
