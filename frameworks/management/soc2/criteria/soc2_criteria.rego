# SOC 2 - AICPA Trust Services Criteria: per-criterion evaluation for all 33 common criteria (CC1.1-CC9.2)
# and all 28 criteria of the optional categories (61 in all). data.soc2.main reads this module and puts the
# criteria of the categories in scope into compliance_report.control_results.
#
# Source: AICPA, TSP section 100, 2017 Trust Services Criteria (points of focus revised 2022; the criteria
# themselves were not changed). The TSC text is (c) AICPA: only the criterion ids are used here, and every
# title below is a short paraphrase written for this library, not AICPA wording.
#
# Basis (one per criterion):
#   evidence     decided from facts the entity's systems report. Each fact names the input path it reads and
#                the test it must meet; limits are never fixed here: where a number is compared it is compared
#                with the entity's own commitment (input.soc2.commitments.<key>).
#   attestation  an organisational criterion. Met only by a signed attestation at
#                input.soc2.attestations["<id>"] = {attested: true, by: "<name>", date: "<date>"}.
#                Six of them (CC1.2, CC1.4, CC3.2, CC7.4, CC9.1, CC9.2) also keep the records the library
#                already read for them (supporting facts): the attestation never passes a criterion whose
#                record says otherwise.
#
# Status: pass | fail | evidence_missing | not_attested (the vocabulary of nist_800_53.main and tisax.main).
#   fail              a fact was supplied and does not meet its test, or the attestation says attested: false
#   not_attested      an attestation is present but not signed ({attested: true, by, date} not all there)
#   evidence_missing  a fact was not supplied (or is not of the expected type), or no attestation is present
#   pass              every fact supplied and met, and (for an attestation criterion) a signed attestation
# Precedence: fail > not_attested > evidence_missing > pass. Only pass is a pass; missing evidence never is.
# There is no separate reason field: the status, the basis and the findings say why a criterion did not pass.

# METADATA
# title: "SOC 2 Trust Services Criteria - per-criterion evaluation of all 33 common criteria and 28 optional-category criteria"
# custom:
#   class: compliance
#   framework: soc2
#   source: aicpa
#   domains: [assurance]
#   coverage:
#     checks: 61
#     cited: 61
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.5.0
package soc2.criteria

import rego.v1

common_criteria_total := 33

# ── Criteria ─────────────────────────────────────────────────────────────────
# category: security for the common criteria; otherwise the optional category the criterion belongs to.
# facts: [{path, test, ...}] with test one of
#   true | false        boolean == true / == false
#   empty               array with no items
#   min_count           array with at least `limit` items
#   all_true            array whose every item has each of `fields` == true; `nonempty: true` also needs one item
#   max_commitment      number <= input.soc2.commitments[`commitment`]
#   min_commitment      number >= input.soc2.commitments[`commitment`]

criteria := {
	"CC1.1": {"title": "Integrity and ethics upheld across the entity", "group": "CC1 control environment", "category": "security", "basis": "attestation"},
	"CC1.2": {
		"title": "Board independent of management and overseeing controls", "group": "CC1 control environment", "category": "security", "basis": "attestation",
		"facts": [
			{"path": "soc2.control_environment.governance.board_oversight", "test": "true"},
			{"path": "soc2.control_environment.governance.management_philosophy", "test": "true"},
			{"path": "soc2.control_environment.integrity.code_of_conduct", "test": "true"},
			{"path": "soc2.control_environment.competence.defined_roles", "test": "true"},
		],
	},
	"CC1.3": {"title": "Reporting lines and authority defined", "group": "CC1 control environment", "category": "security", "basis": "attestation"},
	"CC1.4": {
		"title": "Competent staff hired, developed and kept", "group": "CC1 control environment", "category": "security", "basis": "attestation",
		"facts": [
			{"path": "soc2.human_resources.background_checks", "test": "true"},
			{"path": "soc2.human_resources.training_programs", "test": "true"},
			{"path": "soc2.human_resources.performance_evaluations", "test": "true"},
			{"path": "soc2.human_resources.disciplinary_procedures", "test": "true"},
		],
	},
	"CC1.5": {"title": "Control responsibilities enforced", "group": "CC1 control environment", "category": "security", "basis": "attestation"},
	"CC2.1": {"title": "Quality information supports internal control", "group": "CC2 communication and information", "category": "security", "basis": "attestation"},
	"CC2.2": {"title": "Control duties communicated inside the entity", "group": "CC2 communication and information", "category": "security", "basis": "attestation"},
	"CC2.3": {"title": "Control matters communicated to outside parties", "group": "CC2 communication and information", "category": "security", "basis": "attestation"},
	"CC3.1": {"title": "Objectives clear enough for risk assessment", "group": "CC3 risk assessment", "category": "security", "basis": "attestation"},
	"CC3.2": {
		"title": "Risk identification and analysis", "group": "CC3 risk assessment", "category": "security", "basis": "attestation",
		"facts": [
			{"path": "soc2.risk_management.risk_assessment.periodic", "test": "true"},
			{"path": "soc2.risk_management.risk_assessment.methodology.defined", "test": "true"},
			{"path": "soc2.risk_management.risk_identification.comprehensive", "test": "true"},
			{"path": "soc2.risk_management.risk_response.documented", "test": "true"},
			{"path": "soc2.risk_management.monitoring.continuous", "test": "true"},
			{"path": "soc2.risk_management.reporting.regular", "test": "true"},
			{"path": "soc2.risk_management.escalation.procedures.defined", "test": "true"},
		],
	},
	"CC3.3": {"title": "Fraud risk weighed", "group": "CC3 risk assessment", "category": "security", "basis": "attestation"},
	"CC3.4": {"title": "Changes affecting controls assessed", "group": "CC3 risk assessment", "category": "security", "basis": "attestation"},
	"CC4.1": {"title": "Control components evaluated", "group": "CC4 monitoring activities", "category": "security", "basis": "attestation"},
	"CC4.2": {"title": "Control deficiencies reported and fixed", "group": "CC4 monitoring activities", "category": "security", "basis": "attestation"},
	"CC5.1": {"title": "Control activities that reduce risk", "group": "CC5 control activities", "category": "security", "basis": "attestation"},
	"CC5.2": {"title": "Technology general controls in place", "group": "CC5 control activities", "category": "security", "basis": "attestation"},
	"CC5.3": {"title": "Controls deployed via policy and procedure", "group": "CC5 control activities", "category": "security", "basis": "attestation"},
	"CC6.1": {
		"title": "Logical access to protected systems and data controlled", "group": "CC6 logical and physical access", "category": "security", "basis": "evidence",
		"facts": [
			{"path": "access_controls.privileged_users", "test": "all_true", "fields": ["mfa_enabled"], "nonempty": true},
			{"path": "access_controls.shared_accounts", "test": "empty"},
			{"path": "access_controls.service_accounts", "test": "all_true", "fields": ["unique_identifier", "regular_password_change"]},
			{"path": "network_security.segmentation.enabled", "test": "true"},
			{"path": "network_security.segmentation.zones", "test": "min_count", "limit": 2},
			{"path": "network_security.firewalls.configured", "test": "true"},
			{"path": "database_security.authentication_required", "test": "true"},
			{"path": "database_security.connection_encryption", "test": "true"},
			{"path": "database_security.access_logging", "test": "true"},
			{"path": "database_security.privileged_accounts", "test": "all_true", "fields": ["regular_review"], "nonempty": true},
		],
	},
	"CC6.2": {
		"title": "User access granted on approval, removed and reviewed", "group": "CC6 logical and physical access", "category": "security", "basis": "evidence",
		"facts": [
			{"path": "user_management.automated_provisioning", "test": "true"},
			{"path": "user_management.automated_deprovisioning", "test": "true"},
			{"path": "user_management.approval_workflow", "test": "true"},
			{"path": "access_controls.periodic_reviews.enabled", "test": "true"},
			{"path": "access_controls.periodic_reviews.documented", "test": "true"},
			{"path": "access_controls.periodic_reviews.frequency_days", "test": "max_commitment", "commitment": "access_review_interval_days"},
		],
	},
	"CC6.3": {
		"title": "Role-based, least-privilege access", "group": "CC6 logical and physical access", "category": "security", "basis": "evidence",
		"facts": [
			{"path": "access_controls.role_based_access", "test": "true"},
			{"path": "access_controls.least_privilege_principle", "test": "true"},
			{"path": "access_controls.regular_access_reviews", "test": "true"},
		],
	},
	"CC6.4": {"title": "Physical access restricted", "group": "CC6 logical and physical access", "category": "security", "basis": "attestation"},
	"CC6.5": {
		"title": "Data protected until asset disposal", "group": "CC6 logical and physical access", "category": "security", "basis": "evidence",
		"facts": [
			{"path": "data_disposal.procedures.documented", "test": "true"},
			{"path": "data_disposal.verification.completion_verified", "test": "true"},
		],
	},
	"CC6.6": {
		"title": "Access from outside the system boundary protected", "group": "CC6 logical and physical access", "category": "security", "basis": "evidence",
		"facts": [
			{"path": "remote_access.vpn_required", "test": "true"},
			{"path": "remote_access.vpn_encryption.enabled", "test": "true"},
			{"path": "remote_access.session_timeout.configured", "test": "true"},
			{"path": "remote_access.session_timeout.max_idle_minutes", "test": "max_commitment", "commitment": "max_idle_minutes"},
		],
	},
	"CC6.7": {
		"title": "Information protected in transit and on removal", "group": "CC6 logical and physical access", "category": "security", "basis": "evidence",
		"facts": [
			{"path": "encryption.in_transit.enabled", "test": "true"},
			{"path": "encryption.in_transit.cipher_suites.strong_only", "test": "true"},
			{"path": "dlp.monitoring.enabled", "test": "true"},
		],
	},
	"CC6.8": {
		"title": "Malicious and unauthorised software blocked or found", "group": "CC6 logical and physical access", "category": "security", "basis": "evidence",
		"facts": [
			{"path": "security.edr.coverage.comprehensive", "test": "true"},
			{"path": "security.edr.detection.behavioral", "test": "true"},
		],
	},
	"CC7.1": {
		"title": "Configuration drift and vulnerabilities detected", "group": "CC7 system operations", "category": "security", "basis": "evidence",
		"facts": [
			{"path": "soc2.configuration_management.baseline.established", "test": "true"},
			{"path": "soc2.configuration_management.unauthorized_changes.detection", "test": "true"},
			{"path": "security.vulnerability_management.scanning.continuous", "test": "true"},
			{"path": "security.vulnerability_management.coverage.comprehensive", "test": "true"},
		],
	},
	"CC7.2": {
		"title": "Systems watched for signs of attack or error", "group": "CC7 system operations", "category": "security", "basis": "evidence",
		"facts": [
			{"path": "access_controls.access_logging.enabled", "test": "true"},
			{"path": "access_controls.access_logging.includes_failed_attempts", "test": "true"},
			{"path": "access_controls.access_logging.retention_days", "test": "min_commitment", "commitment": "log_retention_days"},
			{"path": "soc2.monitoring.infrastructure.comprehensive", "test": "true"},
			{"path": "soc2.monitoring.applications.comprehensive", "test": "true"},
			{"path": "soc2.monitoring.security_events.real_time", "test": "true"},
			{"path": "soc2.monitoring.performance.continuous", "test": "true"},
			{"path": "soc2.logging.centralized", "test": "true"},
			{"path": "soc2.logging.integrity_protection", "test": "true"},
			{"path": "soc2.logging.retention.adequate", "test": "true"},
			{"path": "soc2.logging.review.regular", "test": "true"},
		],
	},
	"CC7.3": {"title": "Security events triaged to find incidents", "group": "CC7 system operations", "category": "security", "basis": "attestation"},
	"CC7.4": {
		"title": "Incident response programme operated", "group": "CC7 system operations", "category": "security", "basis": "attestation",
		"facts": [
			{"path": "soc2.incident_response.program.established", "test": "true"},
			{"path": "soc2.incident_response.team.defined", "test": "true"},
			{"path": "soc2.incident_response.procedures.documented", "test": "true"},
			{"path": "soc2.incident_response.testing.regular", "test": "true"},
		],
	},
	"CC7.5": {"title": "Return to normal operation after an incident", "group": "CC7 system operations", "category": "security", "basis": "attestation"},
	"CC8.1": {
		"title": "Changes controlled from request to release", "group": "CC8 change management", "category": "security", "basis": "evidence",
		"facts": [
			{"path": "soc2.change_management.process.documented", "test": "true"},
			{"path": "soc2.change_management.approval.required", "test": "true"},
			{"path": "soc2.change_management.testing.required", "test": "true"},
			{"path": "soc2.change_management.rollback.procedures.defined", "test": "true"},
			{"path": "soc2.configuration_management.baseline.established", "test": "true"},
			{"path": "soc2.configuration_management.version_control", "test": "true"},
			{"path": "soc2.configuration_management.unauthorized_changes.detection", "test": "true"},
		],
	},
	"CC9.1": {
		"title": "Business disruption risk reduced", "group": "CC9 risk mitigation", "category": "security", "basis": "attestation",
		"facts": [
			{"path": "soc2.business_continuity.plan.documented", "test": "true"},
			{"path": "soc2.business_continuity.testing.annual", "test": "true"},
			{"path": "soc2.business_continuity.recovery_objectives.defined", "test": "true"},
			{"path": "soc2.business_continuity.communication.plan.defined", "test": "true"},
		],
	},
	"CC9.2": {
		"title": "Vendor and partner risk handled", "group": "CC9 risk mitigation", "category": "security", "basis": "attestation",
		"facts": [
			{"path": "soc2.vendor_management.due_diligence.performed", "test": "true"},
			{"path": "soc2.vendor_management.contracts.security_requirements", "test": "true"},
			{"path": "soc2.vendor_management.monitoring.ongoing", "test": "true"},
			{"path": "soc2.vendor_management.termination.procedures.defined", "test": "true"},
			{"path": "soc2.subservice_organizations", "test": "all_true", "fields": ["soc_report.current"]},
		],
	},
	"A1.1": {
		"title": "Capacity planned and monitored", "group": "A1 availability", "category": "availability", "basis": "evidence",
		"facts": [
			{"path": "capacity_management.monitoring.enabled", "test": "true"},
			{"path": "capacity_management.forecasting.enabled", "test": "true"},
			{"path": "monitoring.infrastructure.enabled", "test": "true"},
			{"path": "monitoring.alerts.configured", "test": "true"},
		],
	},
	"A1.2": {
		"title": "Backups and recovery infrastructure", "group": "A1 availability", "category": "availability", "basis": "evidence",
		"facts": [
			{"path": "backup.automated_backups.enabled", "test": "true"},
			{"path": "backup.offsite_storage.enabled", "test": "true"},
			{"path": "backup.retention.days", "test": "min_commitment", "commitment": "backup_retention_days"},
		],
	},
	"A1.3": {
		"title": "Recovery testing carried out", "group": "A1 availability", "category": "availability", "basis": "evidence",
		"facts": [{"path": "backup.recovery_testing.frequency_days", "test": "max_commitment", "commitment": "recovery_test_interval_days"}],
	},
	"C1.1": {
		"title": "Confidential data identified and protected", "group": "C1 confidentiality", "category": "confidentiality", "basis": "evidence",
		"facts": [
			{"path": "data_classification.system_defined", "test": "true"},
			{"path": "data_classification.categories.confidential.defined", "test": "true"},
			{"path": "data_classification.access_controls.role_based", "test": "true"},
			{"path": "data_classification.access_controls.need_to_know", "test": "true"},
		],
	},
	"C1.2": {
		"title": "Confidential data disposed of", "group": "C1 confidentiality", "category": "confidentiality", "basis": "evidence",
		"facts": [
			{"path": "data_disposal.procedures.documented", "test": "true"},
			{"path": "data_disposal.verification.completion_verified", "test": "true"},
		],
	},
	"PI1.1": {"title": "Processing specifications defined and communicated", "group": "PI1 processing integrity", "category": "processing_integrity", "basis": "attestation"},
	"PI1.2": {
		"title": "Input validation", "group": "PI1 processing integrity", "category": "processing_integrity", "basis": "evidence",
		"facts": [
			{"path": "data_processing.input_validation.enabled", "test": "true"},
			{"path": "data_processing.input_validation.data_type_checking", "test": "true"},
			{"path": "data_processing.input_validation.range_checking", "test": "true"},
			{"path": "data_processing.input_validation.format_validation", "test": "true"},
		],
	},
	"PI1.3": {
		"title": "Processing authorised and traced", "group": "PI1 processing integrity", "category": "processing_integrity", "basis": "evidence",
		"facts": [
			{"path": "data_processing.authorization.required", "test": "true"},
			{"path": "data_processing.authorization.audit_trail", "test": "true"},
			{"path": "data_processing.error_handling.logging.enabled", "test": "true"},
			{"path": "data_processing.error_handling.recovery_procedures.documented", "test": "true"},
		],
	},
	"PI1.4": {
		"title": "Outputs complete, accurate and delivered as intended", "group": "PI1 processing integrity", "category": "processing_integrity", "basis": "evidence",
		"facts": [
			{"path": "data_processing.transmission.delivery_confirmation", "test": "true"},
			{"path": "data_processing.transactions.reconciliation.enabled", "test": "true"},
			{"path": "data_processing.transactions.reconciliation.frequency_hours", "test": "max_commitment", "commitment": "reconciliation_interval_hours"},
		],
	},
	"PI1.5": {
		"title": "Stored data kept complete and accurate", "group": "PI1 processing integrity", "category": "processing_integrity", "basis": "evidence",
		"facts": [
			{"path": "data_processing.integrity_checks.checksums.enabled", "test": "true"},
			{"path": "databases.integrity_constraints.enforced", "test": "true"},
			{"path": "databases.transactions.rollback_capability", "test": "true"},
		],
	},
	"P1.1": {"title": "Privacy notice given to data subjects", "group": "P1 notice", "category": "privacy", "basis": "attestation"},
	"P2.1": {"title": "Choices and consent explained to data subjects", "group": "P2 choice and consent", "category": "privacy", "basis": "attestation"},
	"P3.1": {
		"title": "Collection limited to stated purposes", "group": "P3 collection", "category": "privacy", "basis": "evidence",
		"facts": [
			{"path": "privacy.collection.policy_documented", "test": "true"},
			{"path": "privacy.collection.purpose_limitation", "test": "true"},
			{"path": "privacy.collection.data_minimization", "test": "true"},
		],
	},
	"P3.2": {
		"title": "Explicit consent recorded", "group": "P3 collection", "category": "privacy", "basis": "evidence",
		"facts": [
			{"path": "privacy.consent.explicit_consent_required", "test": "true"},
			{"path": "privacy.consent.consent_tracking.enabled", "test": "true"},
		],
	},
	"P4.1": {
		"title": "Use limited to stated purposes", "group": "P4 use, retention and disposal", "category": "privacy", "basis": "evidence",
		"facts": [
			{"path": "privacy.use.purpose_limitation", "test": "true"},
			{"path": "privacy.use.compatible_use_only", "test": "true"},
		],
	},
	"P4.2": {
		"title": "Retention schedules applied", "group": "P4 use, retention and disposal", "category": "privacy", "basis": "evidence",
		"facts": [
			{"path": "privacy.retention.policies_documented", "test": "true"},
			{"path": "privacy.retention.retention_schedules.defined", "test": "true"},
		],
	},
	"P4.3": {
		"title": "Personal information disposed of securely", "group": "P4 use, retention and disposal", "category": "privacy", "basis": "evidence",
		"facts": [
			{"path": "privacy.retention.automated_deletion", "test": "true"},
			{"path": "data_disposal.verification.completion_verified", "test": "true"},
		],
	},
	"P5.1": {
		"title": "Data subject access", "group": "P5 access", "category": "privacy", "basis": "evidence",
		"facts": [{"path": "privacy.data_subject_rights.access_request.supported", "test": "true"}],
	},
	"P5.2": {
		"title": "Data subject correction", "group": "P5 access", "category": "privacy", "basis": "evidence",
		"facts": [{"path": "privacy.data_subject_rights.rectification.supported", "test": "true"}],
	},
	"P6.1": {
		"title": "Third-party disclosure controlled", "group": "P6 disclosure and notification", "category": "privacy", "basis": "evidence",
		"facts": [
			{"path": "privacy.third_party_sharing.documented_agreements", "test": "true"},
			{"path": "privacy.third_party_sharing.due_diligence_performed", "test": "true"},
		],
	},
	"P6.2": {
		"title": "Record kept of authorised disclosures", "group": "P6 disclosure and notification", "category": "privacy", "basis": "evidence",
		"facts": [
			{"path": "privacy.third_party_sharing.disclosure_logging.enabled", "test": "true"},
		],
	},
	"P6.3": {"title": "Record kept of unauthorised disclosures", "group": "P6 disclosure and notification", "category": "privacy", "basis": "attestation"},
	"P6.4": {"title": "Privacy commitments obtained from third parties", "group": "P6 disclosure and notification", "category": "privacy", "basis": "attestation"},
	"P6.5": {"title": "Third parties report unauthorised disclosures", "group": "P6 disclosure and notification", "category": "privacy", "basis": "attestation"},
	"P6.6": {
		"title": "Breach notification within commitments", "group": "P6 disclosure and notification", "category": "privacy", "basis": "evidence",
		"facts": [
			{"path": "privacy.breach_notification.procedures_documented", "test": "true"},
			{"path": "privacy.breach_notification.timeline_compliance.authorities", "test": "max_commitment", "commitment": "breach_notice_hours_authorities"},
			{"path": "privacy.breach_notification.timeline_compliance.individuals", "test": "max_commitment", "commitment": "breach_notice_hours_individuals"},
		],
	},
	"P6.7": {
		"title": "Account of personal information held and shared, on request", "group": "P6 disclosure and notification", "category": "privacy", "basis": "evidence",
		"facts": [
			{"path": "privacy.gdpr.records_of_processing", "test": "true"},
			{"path": "privacy.data_subject_requests.request_logging", "test": "true"},
			{"path": "privacy.data_subject_requests.response_timeline", "test": "max_commitment", "commitment": "data_subject_response_days"},
		],
	},
	"P7.1": {
		"title": "Personal data quality maintained", "group": "P7 quality", "category": "privacy", "basis": "evidence",
		"facts": [
			{"path": "privacy.data_quality.accuracy_verification", "test": "true"},
			{"path": "privacy.data_quality.correction_procedures", "test": "true"},
		],
	},
	"P8.1": {"title": "Privacy inquiries, complaints and disputes resolved", "group": "P8 monitoring and enforcement", "category": "privacy", "basis": "attestation"},
}

# Optional-category criteria with no check here (not evaluated, not claimed): none since every one of the 28
# optional-category criteria has a check.
not_mapped := []

common_criteria_ids := {id | some id, c in criteria; c.category == "security"}

# ── Input ────────────────────────────────────────────────────────────────────

_soc2 := input.soc2 if is_object(input.soc2)

else := {}

_attestations := a if {
	a := _soc2.attestations
	is_object(a)
} else := {}

_commitment(key) := v if {
	v := _soc2.commitments[key]
	is_number(v)
}

_path(f) := split(f.path, ".")

_val(f) := v if {
	v := object.get(input, _path(f), null)
} else := null

# ── Facts ────────────────────────────────────────────────────────────────────

_typed(f) if {
	f.test in {"true", "false"}
	is_boolean(_val(f))
}

_typed(f) if {
	f.test in {"empty", "min_count", "all_true"}
	is_array(_val(f))
}

_typed(f) if {
	f.test in {"max_commitment", "min_commitment"}
	is_number(_val(f))
	_commitment(f.commitment)
}

_meets(f) if {
	f.test == "true"
	_val(f) == true
}

_meets(f) if {
	f.test == "false"
	_val(f) == false
}

_meets(f) if {
	f.test == "empty"
	count(_val(f)) == 0
}

_meets(f) if {
	f.test == "min_count"
	count(_val(f)) >= f.limit
}

_meets(f) if {
	f.test == "all_true"
	items := _val(f)
	_nonempty_ok(f, items)
	count([i | some i in items; not _item_ok(f, i)]) == 0
}

_meets(f) if {
	f.test == "max_commitment"
	_val(f) <= _commitment(f.commitment)
}

_meets(f) if {
	f.test == "min_commitment"
	_val(f) >= _commitment(f.commitment)
}

_nonempty_ok(f, _) if object.get(f, "nonempty", false) != true

_nonempty_ok(f, items) if {
	object.get(f, "nonempty", false) == true
	count(items) > 0
}

_item_ok(f, item) if {
	every field in f.fields {
		object.get(item, split(field, "."), null) == true
	}
}

_need(f) := "true" if f.test == "true"

_need(f) := "false" if f.test == "false"

_need(f) := "an empty list" if f.test == "empty"

_need(f) := sprintf("a list of at least %v", [f.limit]) if f.test == "min_count"

_need(f) := sprintf("a %vlist whose every item has %v true", [_nonempty_word(f), concat(" and ", f.fields)]) if f.test == "all_true"

_need(f) := sprintf("at most input.soc2.commitments.%v (%v)", [f.commitment, _commitment(f.commitment)]) if f.test == "max_commitment"

_need(f) := sprintf("at least input.soc2.commitments.%v (%v)", [f.commitment, _commitment(f.commitment)]) if f.test == "min_commitment"

_nonempty_word(f) := "non-empty " if object.get(f, "nonempty", false) == true

else := ""

_shown(f) := sprintf("a list of %v", [count(_val(f))]) if is_array(_val(f))

else := sprintf("%v", [_val(f)])

_facts(id) := object.get(criteria[id], "facts", [])

_missing_facts(id) := sort([m |
	some f in _facts(id)
	not _typed(f)
	some m in _missing_paths(f)
])

_missing_paths(f) := {p |
	some p in [concat("", ["input.", f.path])]
	not _value_typed(f)
} | {p |
	f.test in {"max_commitment", "min_commitment"}
	not _commitment(f.commitment)
	p := sprintf("input.soc2.commitments.%v (the entity's stated value)", [f.commitment])
}

_value_typed(f) if {
	f.test in {"true", "false"}
	is_boolean(_val(f))
}

_value_typed(f) if {
	f.test in {"empty", "min_count", "all_true"}
	is_array(_val(f))
}

_value_typed(f) if {
	f.test in {"max_commitment", "min_commitment"}
	is_number(_val(f))
}

_failed_facts(id) := sort([sprintf("input.%v is %v, required %v", [f.path, _shown(f), _need(f)]) |
	some f in _facts(id)
	_typed(f)
	not _meets(f)
])

# ── Attestations ─────────────────────────────────────────────────────────────

_att(id) := object.get(_attestations, id, null)

_signed(a) if {
	is_object(a)
	a.attested == true
	is_string(a.by)
	trim_space(a.by) != ""
	is_string(a.date)
	trim_space(a.date) != ""
}

_att_path(id) := sprintf("input.soc2.attestations[%q]", [id])

# ── Status per criterion ─────────────────────────────────────────────────────

_attestation_criterion(id) if criteria[id].basis == "attestation"

_refused(a) if {
	is_object(a)
	a.attested == false
}

_status(id) := "fail" if {
	count(_failed_facts(id)) > 0
} else := "fail" if {
	_attestation_criterion(id)
	_refused(_att(id))
} else := "not_attested" if {
	_attestation_criterion(id)
	_att(id) != null
	not _signed(_att(id))
} else := "evidence_missing" if {
	_attestation_criterion(id)
	_att(id) == null
} else := "evidence_missing" if {
	count(_missing_facts(id)) > 0
} else := "pass"

status_of[id] := _status(id) if some id, _ in criteria

_detail_parts(id) := array.concat(
	[concat("", ["fail - ", concat("; ", _failed_facts(id))]) | count(_failed_facts(id)) > 0],
	array.concat(
		[sprintf("fail - %v says attested: false", [_att_path(id)]) |
			_attestation_criterion(id)
			_refused(_att(id))
		],
		array.concat(
			[sprintf("not attested - %v is present but not signed; it must be {attested: true, by: <name>, date: <date>}", [_att_path(id)]) |
				_attestation_criterion(id)
				_att(id) != null
				not _refused(_att(id))
				not _signed(_att(id))
			],
			array.concat(
				[sprintf("evidence missing - no attestation at %v; this organisational criterion is met only by {attested: true, by, date}", [_att_path(id)]) |
					_attestation_criterion(id)
					_att(id) == null
				],
				[sprintf("evidence missing - %v not supplied or not of the expected type", [concat(", ", _missing_facts(id))]) | count(_missing_facts(id)) > 0],
			),
		),
	),
)

findings_of[id] := [sprintf("SOC 2 %v: %v - %v", [id, criteria[id].title, d]) | some d in _detail_parts(id)] if some id, _ in criteria

result_of[id] := {
	"id": id,
	"title": c.title,
	"group": c.group,
	"category": c.category,
	"basis": c.basis,
	"supporting_facts": count(_facts(id)) > 0,
	"status": status_of[id],
	"evidence": sort([concat("", ["input.", f.path]) | some f in _facts(id)]),
	"findings": findings_of[id],
} if some id, c in criteria

# Input problems that are not criteria but still block a compliant result.
input_notes contains sprintf("SOC 2 input: attestation key %q is not a SOC 2 criterion evaluated here", [k]) if {
	some k, _ in _attestations
	not criteria[k]
}

input_notes contains sprintf("SOC 2 input: attestation key %q names an evidence-based criterion; it is decided from facts, the attestation is not read", [k]) if {
	some k, _ in _attestations
	criteria[k].basis == "evidence"
}

input_notes contains "SOC 2 input: input.soc2.attestations is not an object; no attestation can be read" if {
	a := _soc2.attestations
	not is_object(a)
}

# Natural id order: group letters, then the numbers (CC1.1 < CC1.2 < ... < CC9.2 < A1.1 ...).
_sort_key(id) := [_prefix_rank(p[1]), to_number(p[2]), to_number(p[3])] if {
	p := regex.find_all_string_submatch_n(`^([A-Z]+)([0-9]+)\.([0-9]+)$`, id, 1)[0]
}

_prefix_rank(p) := {"CC": 0, "A": 1, "C": 2, "PI": 3, "P": 4}[p]

order := [pair[1] | some pair in sort([[_sort_key(id), id] | some id, _ in criteria])]
