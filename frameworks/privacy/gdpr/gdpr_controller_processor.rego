package gdpr.controller_processor

import rego.v1

# GDPR Articles 24-29 — Controller and Processor Responsibilities
# Defines accountability, joint controllers, processor selection, and contracts

# =============================================================================
# CONTROLLER ACCOUNTABILITY (Article 24)
# =============================================================================

controller_accountability if {
	input.gdpr.controller.policies.documented == true
	input.gdpr.controller.policies.implemented == true
	input.gdpr.controller.policies.reviewed_regularly == true
	input.gdpr.controller.measures_proportionate_to_processing_risk == true
	input.gdpr.controller.technical_organisational_measures.implemented == true
	input.gdpr.controller.compliance_demonstrable == true
}

# Data protection policies
data_protection_policies if {
	input.gdpr.controller.data_protection_policy.documented == true
	input.gdpr.controller.data_protection_policy.approved_by_management == true
	input.gdpr.controller.data_protection_policy.communicated == true
	input.gdpr.controller.data_protection_policy.reviewed_annually == true
	input.gdpr.controller.data_protection_policy.covers_all_processing == true
}

# =============================================================================
# DATA PROTECTION BY DESIGN AND DEFAULT — TECHNICAL DETAIL (Article 25)
# =============================================================================

privacy_by_design_technical if {
	input.gdpr.privacy_by_design.encryption.default_for_personal_data == true
	input.gdpr.privacy_by_design.pseudonymisation.default_where_possible == true
	input.gdpr.privacy_by_design.data_minimisation.technical_controls == true
	input.gdpr.privacy_by_design.purpose_limitation.technical_enforcement == true
	input.gdpr.privacy_by_design.storage_limitation.automated_deletion == true
	input.gdpr.privacy_by_design.access_controls.privacy_protective_defaults == true
}

privacy_by_default if {
	input.gdpr.privacy_by_default.settings.most_private_by_default == true
	input.gdpr.privacy_by_default.data_collection.minimum_required == true
	input.gdpr.privacy_by_default.retention.shortest_necessary == true
	input.gdpr.privacy_by_default.access.limited_to_minimum_necessary == true
	input.gdpr.privacy_by_default.opt_in.required_not_opt_out == true
}

# =============================================================================
# JOINT CONTROLLERS (Article 26)
# =============================================================================

joint_controller_arrangement if {
	not input.gdpr.joint_controllers.arrangement_exists
} else if {
	input.gdpr.joint_controllers.arrangement_exists
	input.gdpr.joint_controllers.agreement.documented == true
	input.gdpr.joint_controllers.responsibilities.defined == true
	input.gdpr.joint_controllers.data_subjects.can_exercise_rights_against_either == true
	input.gdpr.joint_controllers.contact_point.designated == true
	input.gdpr.joint_controllers.agreement.essence_available_to_data_subjects == true
}

# =============================================================================
# PROCESSORS (Articles 28-29)
# =============================================================================

# Processor selection due diligence
processor_due_diligence if {
	input.gdpr.processors.selection.security_capabilities_assessed == true
	input.gdpr.processors.selection.technical_measures_verified == true
	input.gdpr.processors.selection.only_gdpr_compliant_processors == true
	input.gdpr.processors.selection.documented_assessment == true
}

# Article 28(3) processor contract requirements
processor_contract if {
	input.gdpr.processors.contract.processing_only_on_instructions == true
	input.gdpr.processors.contract.confidentiality.staff_bound == true
	input.gdpr.processors.contract.security_measures.article_32_compliant == true
	input.gdpr.processors.contract.sub_processors.prior_authorisation_required == true
	input.gdpr.processors.contract.data_subject_rights.assistance_provided == true
	input.gdpr.processors.contract.deletion_return.on_contract_end == true
	input.gdpr.processors.contract.audit_rights.controller_can_audit == true
	input.gdpr.processors.contract.information.provided_to_controller == true
}

# Sub-processor chain management
sub_processor_management if {
	input.gdpr.sub_processors.inventory.maintained == true
	input.gdpr.sub_processors.authorisation.controller_approval == true
	input.gdpr.sub_processors.contracts.same_obligations_as_processor == true
	input.gdpr.sub_processors.liability.processor_remains_liable == true
	input.gdpr.sub_processors.changes.controller_notified == true
}

# Processor staff obligations
processor_staff_obligations if {
	input.gdpr.processors.staff.confidentiality_bound == true
	input.gdpr.processors.staff.processing_only_on_instructions == true
	input.gdpr.processors.staff.training.gdpr_awareness == true
}

# =============================================================================
# RECORDS OF PROCESSING (Article 30 — detailed)
# =============================================================================

controller_records if {
	input.gdpr.rop.controller.name_and_contact.documented == true
	input.gdpr.rop.controller.dpo_contact.documented == true
	input.gdpr.rop.controller.purposes.documented == true
	input.gdpr.rop.controller.categories_of_data_subjects.documented == true
	input.gdpr.rop.controller.categories_of_personal_data.documented == true
	input.gdpr.rop.controller.recipients.documented == true
	input.gdpr.rop.controller.third_country_transfers.documented == true
	input.gdpr.rop.controller.retention_periods.documented == true
	input.gdpr.rop.controller.security_measures.documented == true
}

processor_records if {
	input.gdpr.rop.processor.name_and_contact.documented == true
	input.gdpr.rop.processor.controllers_processed_for.documented == true
	input.gdpr.rop.processor.categories_of_processing.documented == true
	input.gdpr.rop.processor.third_country_transfers.documented == true
	input.gdpr.rop.processor.security_measures.documented == true
}

# =============================================================================
# COOPERATION WITH SUPERVISORY AUTHORITY (Article 31)
# =============================================================================

supervisory_authority_cooperation if {
	input.gdpr.supervisory_authority.cooperation.policy == true
	input.gdpr.supervisory_authority.requests.response_procedure == true
	input.gdpr.supervisory_authority.investigations.documented_process == true
}

# =============================================================================
# SECURITY OF PROCESSING (Article 32)
# =============================================================================

security_of_processing if {
	input.gdpr.security.risk_assessment.performed == true
	input.gdpr.security.pseudonymisation.implemented == true
	input.gdpr.security.encryption.implemented == true
	input.gdpr.security.confidentiality.ensured == true
	input.gdpr.security.integrity.ensured == true
	input.gdpr.security.availability.ensured == true
	input.gdpr.security.resilience.ensured == true
	input.gdpr.security.restore_capability.tested == true
	input.gdpr.security.effectiveness.regularly_tested == true
	input.gdpr.security.measures.proportionate_to_risk == true
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	controller_accountability
	data_protection_policies
	privacy_by_design_technical
	privacy_by_default
	processor_due_diligence
	processor_contract
	sub_processor_management
	controller_records
	processor_records
	security_of_processing
}

report := {
	"standard": "GDPR Articles 24-32 — Controller/Processor Accountability",
	"compliant": compliant,
	"controller": {
		"accountability": controller_accountability,
		"data_protection_policies": data_protection_policies,
		"records_of_processing": controller_records,
	},
	"privacy_by_design": {
		"technical_measures": privacy_by_design_technical,
		"privacy_by_default": privacy_by_default,
	},
	"joint_controllers": joint_controller_arrangement,
	"processors": {
		"due_diligence": processor_due_diligence,
		"contract_requirements": processor_contract,
		"sub_processor_management": sub_processor_management,
		"staff_obligations": processor_staff_obligations,
		"records_of_processing": processor_records,
	},
	"supervisory_authority": supervisory_authority_cooperation,
	"security_of_processing": security_of_processing,
}
