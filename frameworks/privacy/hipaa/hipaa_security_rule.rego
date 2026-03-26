package hipaa.security_rule

import rego.v1

# HIPAA Security Rule (45 CFR Part 164)
# Technical, Administrative, and Physical Safeguards for
# Electronic Protected Health Information (ePHI)
#
# OPA endpoint: POST http://<opa-host>:8182/v1/data/hipaa/security_rule/report
#
# Input shape: input.hipaa.*

# =============================================================================
# ADMINISTRATIVE SAFEGUARDS (§164.308)
# =============================================================================

# §164.308(a)(1) - Security Management Process
security_management_process if {
	input.hipaa.administrative.security_management.risk_analysis.conducted == true
	input.hipaa.administrative.security_management.risk_analysis.documented == true
	input.hipaa.administrative.security_management.risk_analysis.frequency_months <= 12
	input.hipaa.administrative.security_management.risk_management.implemented == true
	input.hipaa.administrative.security_management.sanction_policy.established == true
	input.hipaa.administrative.security_management.activity_review.conducted == true
}

# §164.308(a)(2) - Assigned Security Responsibility
assigned_security_responsibility if {
	input.hipaa.administrative.security_officer.designated == true
	input.hipaa.administrative.security_officer.documented == true
	input.hipaa.administrative.security_officer.responsibilities.defined == true
}

# §164.308(a)(3) - Workforce Security
workforce_security if {
	input.hipaa.administrative.workforce.authorization_supervision.implemented == true
	input.hipaa.administrative.workforce.clearance_procedure.implemented == true
	input.hipaa.administrative.workforce.termination_procedures.implemented == true
	input.hipaa.administrative.workforce.access_removed_on_termination == true
}

# §164.308(a)(4) - Information Access Management
information_access_management if {
	input.hipaa.administrative.access_management.isolating_clearinghouse_functions.addressed == true
	input.hipaa.administrative.access_management.access_authorization.implemented == true
	input.hipaa.administrative.access_management.access_establishment.implemented == true
	input.hipaa.administrative.access_management.least_privilege.enforced == true
}

# §164.308(a)(5) - Security Awareness and Training
security_awareness_training if {
	input.hipaa.administrative.training.program.implemented == true
	input.hipaa.administrative.training.frequency_months <= 12
	input.hipaa.administrative.training.new_hires.required == true
	input.hipaa.administrative.training.malicious_software.covered == true
	input.hipaa.administrative.training.log_in_monitoring.covered == true
	input.hipaa.administrative.training.password_management.covered == true
}

# §164.308(a)(6) - Security Incident Procedures
security_incident_procedures if {
	input.hipaa.administrative.incident_response.response_procedures.implemented == true
	input.hipaa.administrative.incident_response.reporting.implemented == true
	input.hipaa.administrative.incident_response.breach_notification.procedures_defined == true
	input.hipaa.administrative.incident_response.forensic_capability.available == true
}

# §164.308(a)(7) - Contingency Plan
contingency_plan if {
	input.hipaa.administrative.contingency.data_backup.plan_implemented == true
	input.hipaa.administrative.contingency.disaster_recovery.plan_implemented == true
	input.hipaa.administrative.contingency.emergency_mode.plan_implemented == true
	input.hipaa.administrative.contingency.testing.performed == true
	input.hipaa.administrative.contingency.testing.frequency_months <= 12
	input.hipaa.administrative.contingency.applications.criticality_analysis_performed == true
}

# §164.308(a)(8) - Evaluation
periodic_technical_evaluation if {
	input.hipaa.administrative.evaluation.periodic_technical.performed == true
	input.hipaa.administrative.evaluation.frequency_months <= 12
	input.hipaa.administrative.evaluation.environmental_operations_changes.trigger_review == true
}

# §164.308(b)(1) - Business Associate Contracts
business_associate_contracts if {
	input.hipaa.administrative.business_associates.contracts.required == true
	input.hipaa.administrative.business_associates.contracts.phi_safeguards.required == true
	input.hipaa.administrative.business_associates.inventory.maintained == true
	input.hipaa.administrative.business_associates.compliance.monitored == true
}

# =============================================================================
# PHYSICAL SAFEGUARDS (§164.310)
# =============================================================================

# §164.310(a)(1) - Facility Access Controls
facility_access_controls if {
	input.hipaa.physical.facility_access.contingency_operations.addressed == true
	input.hipaa.physical.facility_access.facility_security_plan.implemented == true
	input.hipaa.physical.facility_access.access_control.implemented == true
	input.hipaa.physical.facility_access.maintenance_records.tracked == true
}

# §164.310(b) - Workstation Use
workstation_use_controls if {
	input.hipaa.physical.workstation_use.policies.implemented == true
	input.hipaa.physical.workstation_use.physical_access.restricted == true
	input.hipaa.physical.workstation_use.screen_lock.configured == true
}

# §164.310(c) - Workstation Security
workstation_security if {
	input.hipaa.physical.workstation_security.physical_safeguards.implemented == true
	input.hipaa.physical.workstation_security.ephi_access.restricted == true
}

# §164.310(d)(1) - Device and Media Controls
device_media_controls if {
	input.hipaa.physical.device_media.disposal.procedures_implemented == true
	input.hipaa.physical.device_media.disposal.ephi_wiped == true
	input.hipaa.physical.device_media.media_reuse.sanitization_implemented == true
	input.hipaa.physical.device_media.accountability.tracked == true
	input.hipaa.physical.device_media.data_backup.copy_made_before_movement == true
}

# =============================================================================
# TECHNICAL SAFEGUARDS (§164.312)
# =============================================================================

# §164.312(a)(1) - Access Control
technical_access_control if {
	input.hipaa.technical.access_control.unique_user_id.assigned == true
	input.hipaa.technical.access_control.emergency_access.procedure_defined == true
	input.hipaa.technical.access_control.automatic_logoff.implemented == true
	input.hipaa.technical.access_control.automatic_logoff.timeout_minutes <= 15
	input.hipaa.technical.access_control.encryption.ephi_at_rest == true
}

# §164.312(b) - Audit Controls
audit_controls if {
	input.hipaa.technical.audit_controls.hardware.logging_enabled == true
	input.hipaa.technical.audit_controls.software.logging_enabled == true
	input.hipaa.technical.audit_controls.ephi_access.logged == true
	input.hipaa.technical.audit_controls.logs.reviewed_regularly == true
	input.hipaa.technical.audit_controls.logs.retention_years >= 6
	input.hipaa.technical.audit_controls.tamper_protection.implemented == true
}

# §164.312(c)(1) - Integrity
ephi_integrity if {
	input.hipaa.technical.integrity.ephi_not_improperly_altered == true
	input.hipaa.technical.integrity.transmission_integrity.controls_implemented == true
	input.hipaa.technical.integrity.hash_verification.implemented == true
}

# §164.312(d) - Person or Entity Authentication
entity_authentication if {
	input.hipaa.technical.authentication.mfa.implemented == true
	input.hipaa.technical.authentication.identity_verification.implemented == true
	input.hipaa.technical.authentication.password_policy.enforced == true
	input.hipaa.technical.authentication.password_policy.min_length >= 8
	input.hipaa.technical.authentication.password_policy.complexity_required == true
	input.hipaa.technical.authentication.failed_login_lockout.implemented == true
}

# §164.312(e)(1) - Transmission Security
transmission_security if {
	input.hipaa.technical.transmission.encryption.ephi_in_transit == true
	input.hipaa.technical.transmission.tls.minimum_version >= "1.2"
	input.hipaa.technical.transmission.network_controls.implemented == true
	input.hipaa.technical.transmission.integrity_controls.implemented == true
}

# =============================================================================
# BREACH NOTIFICATION RULE (§164.400-§164.414)
# =============================================================================

breach_notification_procedures if {
	input.hipaa.breach_notification.policy.documented == true
	input.hipaa.breach_notification.individual_notification.within_60_days == true
	input.hipaa.breach_notification.hhs_notification.annual_report == true
	input.hipaa.breach_notification.hhs_notification.large_breach.within_60_days == true
	input.hipaa.breach_notification.media_notification.large_breach_500_plus == true
	input.hipaa.breach_notification.risk_assessment.four_factor_test.performed == true
}

# =============================================================================
# PRIVACY RULE - KEY TECHNICAL CONTROLS (§164.500+)
# =============================================================================

minimum_necessary_controls if {
	input.hipaa.privacy.minimum_necessary.policy.implemented == true
	input.hipaa.privacy.minimum_necessary.access_limited_to_job_function == true
	input.hipaa.privacy.minimum_necessary.role_based_access.implemented == true
}

patient_rights_technical if {
	input.hipaa.privacy.patient_rights.access_to_phi.process_defined == true
	input.hipaa.privacy.patient_rights.amendment.process_defined == true
	input.hipaa.privacy.patient_rights.accounting_of_disclosures.maintained == true
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

administrative_safeguards_compliant if {
	security_management_process
	assigned_security_responsibility
	workforce_security
	information_access_management
	security_awareness_training
	security_incident_procedures
	contingency_plan
	periodic_technical_evaluation
	business_associate_contracts
}

physical_safeguards_compliant if {
	facility_access_controls
	workstation_use_controls
	workstation_security
	device_media_controls
}

technical_safeguards_compliant if {
	technical_access_control
	audit_controls
	ephi_integrity
	entity_authentication
	transmission_security
}

default compliant := false

compliant if {
	administrative_safeguards_compliant
	physical_safeguards_compliant
	technical_safeguards_compliant
	breach_notification_procedures
	minimum_necessary_controls
}

report := {
	"standard": "HIPAA Security Rule (45 CFR Part 164)",
	"compliant": compliant,
	"safeguards": {
		"administrative": {
			"compliant": administrative_safeguards_compliant,
			"security_management_process": security_management_process,
			"assigned_security_responsibility": assigned_security_responsibility,
			"workforce_security": workforce_security,
			"information_access_management": information_access_management,
			"security_awareness_training": security_awareness_training,
			"security_incident_procedures": security_incident_procedures,
			"contingency_plan": contingency_plan,
			"periodic_evaluation": periodic_technical_evaluation,
			"business_associate_contracts": business_associate_contracts,
		},
		"physical": {
			"compliant": physical_safeguards_compliant,
			"facility_access_controls": facility_access_controls,
			"workstation_use": workstation_use_controls,
			"workstation_security": workstation_security,
			"device_media_controls": device_media_controls,
		},
		"technical": {
			"compliant": technical_safeguards_compliant,
			"access_control": technical_access_control,
			"audit_controls": audit_controls,
			"integrity": ephi_integrity,
			"authentication": entity_authentication,
			"transmission_security": transmission_security,
		},
	},
	"breach_notification": breach_notification_procedures,
	"privacy_controls": {
		"minimum_necessary": minimum_necessary_controls,
		"patient_rights": patient_rights_technical,
	},
}
