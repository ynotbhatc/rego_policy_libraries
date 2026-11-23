# METADATA
# title: "Defaults so report/details never collapse to {} on empty input"
# custom:
#   class: compliance
#   framework: gdpr
#   source: eu
#   domains: [privacy, eu]
#   coverage:
#     checks: 27
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.5.0
package gdpr.compliance

import rego.v1

# Defaults so report/details never collapse to {} on empty input
default lawful_basis_established := false

default consent_management := false

default special_category_data := false

default right_of_access := false

default right_to_rectification := false

default right_to_erasure := false

default right_to_portability := false

default right_to_object := false

default privacy_by_design := false

default dpia_process := false

default dpo_requirements := false

default records_of_processing := false

default breach_notification := false

default international_transfers := false

default encryption_pseudonymisation := false

default ongoing_confidentiality_integrity := false

default restore_and_test := false

default data_retention := false

default data_minimisation := false

default processor_agreements := false

# GDPR - General Data Protection Regulation (EU) 2016/679
# Technical and organizational measures for personal data protection
#
# OPA endpoint: POST http://<opa-host>:8182/v1/data/gdpr/compliance/report

# =============================================================================
# CONDITIONAL OBLIGATIONS — APPLICABILITY
# =============================================================================
# Three obligations in this module apply only on a condition: Art. 9 (special categories are processed),
# Art. 37(1) (a data protection officer must be designated) and Chapter V, Art. 44-49 (personal data is
# transferred to a third country or international organisation).
# Whether the condition holds is a fact the collector states as a boolean. Only the boolean false is an
# exemption and only the boolean true selects the evidence branch. A fact that is absent, null or not a
# boolean (the string "false", 0, an empty object) is missing evidence: the gate fails and the fact is
# listed under evidence_missing. Nothing is read as "not applicable" because it was not collected.

_conditional := {
	"special_category_data": {
		"article": "Art. 9",
		"field": "input.gdpr.special_category_data.processed",
		"question": "state whether special categories of personal data (Art. 9(1)) are processed",
	},
	"dpo_requirements": {
		"article": "Art. 37",
		"field": "input.gdpr.dpo.mandatory",
		"question": "state whether a data protection officer must be designated under Art. 37(1)",
	},
	"international_transfers": {
		"article": "Art. 44-49",
		"field": "input.gdpr.international_transfers.occur",
		"question": "state whether personal data is transferred to a third country or international organisation",
	},
}

# The stated condition, read once per gate. One rule per gate, so a gate whose fact cannot be read (no
# input at all, a null or non-object section) is undefined on its own and falls to evidence_missing.
_stated["special_category_data"] := object.get(input, ["gdpr", "special_category_data", "processed"], null)

_stated["dpo_requirements"] := object.get(input, ["gdpr", "dpo", "mandatory"], null)

_stated["international_transfers"] := object.get(input, ["gdpr", "international_transfers", "occur"], null)

# applicable | not_applicable | evidence_missing, per gate
applicability[name] := _applicability(name) if some name, _ in _conditional

_applicability(name) := "applicable" if {
	_stated[name] == true
} else := "not_applicable" if {
	_stated[name] == false
} else := "evidence_missing"

_fact_text(name) := sprintf("got %v", [json.marshal(_stated[name])]) if {
	_stated[name] != null
} else := "not collected"

evidence_missing := [finding |
	some name in sort(object.keys(_conditional))
	applicability[name] == "evidence_missing"
	gate := _conditional[name]
	finding := {
		"control": name,
		"article": gate.article,
		"status": "evidence_missing",
		"path": gate.field,
		"title": sprintf(
			"GDPR %v (%v): evidence missing — %v must be true or false (%v); %v",
			[gate.article, name, gate.field, _fact_text(name), gate.question],
		),
	}
]

# =============================================================================
# LAWFUL BASIS FOR PROCESSING (Articles 6, 7, 9)
# =============================================================================

lawful_basis_established if {
	input.gdpr.lawful_basis.documented == true
	input.gdpr.lawful_basis.recorded_per_processing_activity == true
	input.gdpr.lawful_basis.reviewed_regularly == true
}

consent_management if {
	input.gdpr.consent.freely_given == true
	input.gdpr.consent.specific == true
	input.gdpr.consent.informed == true
	input.gdpr.consent.unambiguous == true
	input.gdpr.consent.records_maintained == true
	input.gdpr.consent.withdrawal_as_easy_as_giving == true
	input.gdpr.consent.pre_ticked_boxes.not_used == true
}

special_category_data if {
	applicability.special_category_data == "not_applicable"
} else if {
	applicability.special_category_data == "applicable"
	input.gdpr.special_category_data.explicit_consent == true
	input.gdpr.special_category_data.legal_basis.documented == true
	input.gdpr.special_category_data.dpia.conducted == true
	input.gdpr.special_category_data.additional_safeguards.implemented == true
}

# =============================================================================
# DATA SUBJECT RIGHTS (Articles 12-23)
# =============================================================================

right_of_access if {
	input.gdpr.data_subject_rights.access.process_defined == true
	input.gdpr.data_subject_rights.access.response_within_30_days == true
	input.gdpr.data_subject_rights.access.identity_verification == true
	input.gdpr.data_subject_rights.access.free_of_charge == true
}

right_to_rectification if {
	input.gdpr.data_subject_rights.rectification.process_defined == true
	input.gdpr.data_subject_rights.rectification.third_parties_notified == true
}

right_to_erasure if {
	input.gdpr.data_subject_rights.erasure.process_defined == true
	input.gdpr.data_subject_rights.erasure.secure_deletion_implemented == true
	input.gdpr.data_subject_rights.erasure.third_parties_notified == true
	input.gdpr.data_subject_rights.erasure.backups_addressed == true
}

right_to_portability if {
	input.gdpr.data_subject_rights.portability.structured_format_available == true
	input.gdpr.data_subject_rights.portability.machine_readable == true
	input.gdpr.data_subject_rights.portability.common_format_used == true
}

right_to_object if {
	input.gdpr.data_subject_rights.objection.process_defined == true
	input.gdpr.data_subject_rights.objection.direct_marketing.always_honoured == true
}

# =============================================================================
# DATA PROTECTION BY DESIGN AND DEFAULT (Article 25)
# =============================================================================

privacy_by_design if {
	input.gdpr.privacy_by_design.principles.data_minimisation == true
	input.gdpr.privacy_by_design.principles.purpose_limitation == true
	input.gdpr.privacy_by_design.principles.storage_limitation == true
	input.gdpr.privacy_by_design.implemented_at_design_phase == true
	input.gdpr.privacy_by_design.default_settings.privacy_protective == true
	input.gdpr.privacy_by_design.sdlc_integrated == true
}

# =============================================================================
# DATA PROTECTION IMPACT ASSESSMENT (Article 35)
# =============================================================================

dpia_process if {
	input.gdpr.dpia.policy.documented == true
	input.gdpr.dpia.high_risk_processing.triggers_dpia == true
	input.gdpr.dpia.new_technologies.triggers_dpia == true
	input.gdpr.dpia.large_scale_monitoring.triggers_dpia == true
	input.gdpr.dpia.dpo.consulted == true
	input.gdpr.dpia.results.documented == true
}

# =============================================================================
# DATA PROTECTION OFFICER (Article 37-39)
# =============================================================================

dpo_requirements if {
	# Designation is mandatory only in the Art. 37(1) cases; the organisation states which side it is on.
	applicability.dpo_requirements == "not_applicable"
} else if {
	applicability.dpo_requirements == "applicable"
	input.gdpr.dpo.appointed == true
	input.gdpr.dpo.contact_details.published == true
	input.gdpr.dpo.contact_details.notified_to_supervisory_authority == true
	input.gdpr.dpo.independence.guaranteed == true
	input.gdpr.dpo.resources.adequate == true
}

# =============================================================================
# RECORDS OF PROCESSING ACTIVITIES (Article 30)
# =============================================================================

records_of_processing if {
	input.gdpr.records_of_processing.maintained == true
	input.gdpr.records_of_processing.controller_record.complete == true
	input.gdpr.records_of_processing.includes.purposes == true
	input.gdpr.records_of_processing.includes.data_categories == true
	input.gdpr.records_of_processing.includes.recipients == true
	input.gdpr.records_of_processing.includes.retention_periods == true
	input.gdpr.records_of_processing.includes.security_measures == true
	input.gdpr.records_of_processing.regularly_reviewed == true
}

# =============================================================================
# DATA BREACH NOTIFICATION (Articles 33-34)
# =============================================================================

breach_notification if {
	input.gdpr.breach_notification.policy.documented == true
	input.gdpr.breach_notification.detection.controls_in_place == true
	input.gdpr.breach_notification.supervisory_authority.within_72_hours == true
	input.gdpr.breach_notification.risk_assessment.performed == true
	input.gdpr.breach_notification.data_subjects.notified_when_high_risk == true
	input.gdpr.breach_notification.register.maintained == true
}

# =============================================================================
# INTERNATIONAL TRANSFERS (Articles 44-49)
# =============================================================================

international_transfers if {
	applicability.international_transfers == "not_applicable"
} else if {
	applicability.international_transfers == "applicable"
	input.gdpr.international_transfers.adequacy_decision_or_safeguards == true
	input.gdpr.international_transfers.mechanism.documented == true
	input.gdpr.international_transfers.scc_or_bcr.implemented == true
	input.gdpr.international_transfers.data_subjects.informed == true
}

# =============================================================================
# TECHNICAL SECURITY MEASURES (Article 32)
# =============================================================================

encryption_pseudonymisation if {
	input.gdpr.technical_measures.encryption.personal_data_at_rest == true
	input.gdpr.technical_measures.encryption.personal_data_in_transit == true
	input.gdpr.technical_measures.pseudonymisation.implemented == true
	input.gdpr.technical_measures.anonymisation.process_defined == true
}

ongoing_confidentiality_integrity if {
	input.gdpr.technical_measures.confidentiality.access_controls == true
	input.gdpr.technical_measures.integrity.checksums_or_signatures == true
	input.gdpr.technical_measures.availability.backup_and_recovery == true
	input.gdpr.technical_measures.resilience.systems_resilient == true
}

restore_and_test if {
	input.gdpr.technical_measures.restore.timely_restoration_capability == true
	input.gdpr.technical_measures.testing.regular_security_testing == true
	input.gdpr.technical_measures.testing.effectiveness_evaluated == true
}

# =============================================================================
# DATA RETENTION AND MINIMISATION (Articles 5, 17)
# =============================================================================

data_retention if {
	input.gdpr.retention.policy.documented == true
	input.gdpr.retention.periods.defined_per_category == true
	input.gdpr.retention.automated_deletion.implemented == true
	input.gdpr.retention.review.regular == true
	input.gdpr.retention.legal_hold.process_defined == true
}

data_minimisation if {
	input.gdpr.data_minimisation.collection_limited_to_purpose == true
	input.gdpr.data_minimisation.fields_reviewed_regularly == true
	input.gdpr.data_minimisation.unnecessary_data.not_collected == true
}

# =============================================================================
# THIRD PARTY / PROCESSOR MANAGEMENT (Article 28)
# =============================================================================

processor_agreements if {
	input.gdpr.processors.contracts.required == true
	input.gdpr.processors.contracts.article_28_compliant == true
	input.gdpr.processors.contracts.processing_instructions_documented == true
	input.gdpr.processors.contracts.sub_processor_approval.required == true
	input.gdpr.processors.inventory.maintained == true
	input.gdpr.processors.due_diligence.performed == true
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	lawful_basis_established
	consent_management
	special_category_data
	right_of_access
	right_to_rectification
	right_to_erasure
	right_to_portability
	right_to_object
	privacy_by_design
	dpia_process
	dpo_requirements
	records_of_processing
	breach_notification
	international_transfers
	encryption_pseudonymisation
	ongoing_confidentiality_integrity
	restore_and_test
	data_retention
	data_minimisation
	processor_agreements
}

report := {
	"standard": "GDPR (EU) 2016/679",
	"compliant": compliant,
	"lawfulness_of_processing": {
		"lawful_basis": lawful_basis_established,
		"consent_management": consent_management,
		"special_category_data": special_category_data,
	},
	"data_subject_rights": {
		"right_of_access": right_of_access,
		"right_to_rectification": right_to_rectification,
		"right_to_erasure": right_to_erasure,
		"right_to_portability": right_to_portability,
		"right_to_object": right_to_object,
	},
	"accountability": {
		"privacy_by_design": privacy_by_design,
		"dpia_process": dpia_process,
		"dpo_requirements": dpo_requirements,
		"records_of_processing": records_of_processing,
	},
	"incident_management": {"breach_notification": breach_notification},
	"international_transfers": international_transfers,
	"technical_measures": {
		"encryption_pseudonymisation": encryption_pseudonymisation,
		"confidentiality_integrity": ongoing_confidentiality_integrity,
		"restore_and_test": restore_and_test,
	},
	"data_governance": {
		"retention": data_retention,
		"minimisation": data_minimisation,
		"processor_agreements": processor_agreements,
	},
	"applicability": applicability,
	"evidence_missing": evidence_missing,
}
