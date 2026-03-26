package gdpr.data_transfers

import rego.v1

# GDPR Chapter V (Articles 44-49) — Transfers of Personal Data to Third Countries
# Ensures that personal data transferred outside the EEA maintains GDPR-equivalent protection

# =============================================================================
# GENERAL PRINCIPLES (Article 44)
# =============================================================================

transfer_principles if {
	input.gdpr.transfers.general.adequacy_or_safeguards.in_place == true
	input.gdpr.transfers.general.onward_transfers.restricted == true
	input.gdpr.transfers.general.compliance_documented == true
}

# =============================================================================
# ADEQUACY DECISIONS (Article 45)
# =============================================================================

adequacy_decision if {
	# Organisation transfers only to adequacy-listed countries
	input.gdpr.transfers.adequacy.countries_verified == true
	input.gdpr.transfers.adequacy.list_current == true
	input.gdpr.transfers.adequacy.monitoring.for_withdrawal == true
}

# Countries with current adequacy decisions (EDPB maintained list)
adequacy_countries := {
	"Andorra",
	"Argentina",
	"Canada",
	"Faroe Islands",
	"Guernsey",
	"Isle of Man",
	"Israel",
	"Japan",
	"Jersey",
	"New Zealand",
	"Republic of Korea",
	"Switzerland",
	"United Kingdom",
	"United States",  # EU-US Data Privacy Framework (since 2023)
	"Uruguay",
}

transfer_to_adequate_country if {
	some country in input.gdpr.transfers.destination_countries
	country in adequacy_countries
}

# =============================================================================
# STANDARD CONTRACTUAL CLAUSES (Article 46(2)(c))
# =============================================================================

standard_contractual_clauses if {
	input.gdpr.transfers.scc.used == true
	input.gdpr.transfers.scc.eu_commission_approved_version == true
	input.gdpr.transfers.scc.signed_by_parties == true
	input.gdpr.transfers.scc.not_amended_invalidly == true
	input.gdpr.transfers.scc.transfer_impact_assessment.performed == true
}

# Transfer Impact Assessment (TIA) for SCCs
transfer_impact_assessment if {
	input.gdpr.transfers.tia.performed == true
	input.gdpr.transfers.tia.destination_country_laws.assessed == true
	input.gdpr.transfers.tia.public_authority_access.assessed == true
	input.gdpr.transfers.tia.documented == true
	input.gdpr.transfers.tia.supplementary_measures.identified_if_needed == true
}

# Supplementary measures when TIA identifies risks
supplementary_measures if {
	not input.gdpr.transfers.tia.supplementary_measures_required
} else if {
	input.gdpr.transfers.tia.supplementary_measures_required
	input.gdpr.transfers.supplementary_measures.technical.end_to_end_encryption == true
	input.gdpr.transfers.supplementary_measures.technical.pseudonymisation == true
	input.gdpr.transfers.supplementary_measures.contractual.additional_commitments == true
	input.gdpr.transfers.supplementary_measures.effective == true
}

# =============================================================================
# BINDING CORPORATE RULES (Article 47)
# =============================================================================

binding_corporate_rules if {
	not input.gdpr.transfers.bcr.used
} else if {
	input.gdpr.transfers.bcr.used
	input.gdpr.transfers.bcr.approved_by_lead_dpa == true
	input.gdpr.transfers.bcr.legally_binding == true
	input.gdpr.transfers.bcr.covers_all_entities == true
	input.gdpr.transfers.bcr.enforceable_by_data_subjects == true
	input.gdpr.transfers.bcr.published == true
	input.gdpr.transfers.bcr.dpo_responsible == true
}

# =============================================================================
# EU-US DATA PRIVACY FRAMEWORK (Successor to Privacy Shield)
# =============================================================================

eu_us_dpf if {
	not input.gdpr.transfers.us_transfers.occur
} else if {
	input.gdpr.transfers.us_transfers.occur
	input.gdpr.transfers.us_transfers.mechanism.eu_us_dpf_or_scc == true
	input.gdpr.transfers.us_transfers.recipient.certified_or_scc_signed == true
	input.gdpr.transfers.us_transfers.dpf_certification.verified == true
}

# =============================================================================
# DEROGATIONS FOR SPECIFIC SITUATIONS (Article 49)
# =============================================================================

derogation_if_used if {
	not input.gdpr.transfers.derogations.used
} else if {
	input.gdpr.transfers.derogations.used
	input.gdpr.transfers.derogations.basis.documented == true

	# Derogation must be one of the allowed bases
	allowed_derogation_used
}

allowed_derogation_used if {
	input.gdpr.transfers.derogations.basis.explicit_consent == true
} else if {
	input.gdpr.transfers.derogations.basis.contract_performance == true
} else if {
	input.gdpr.transfers.derogations.basis.public_interest == true
} else if {
	input.gdpr.transfers.derogations.basis.legal_claims == true
} else if {
	input.gdpr.transfers.derogations.basis.vital_interests == true
}

# =============================================================================
# TRANSFER GOVERNANCE
# =============================================================================

transfer_inventory if {
	input.gdpr.transfers.inventory.maintained == true
	input.gdpr.transfers.inventory.all_third_country_flows.documented == true
	input.gdpr.transfers.inventory.mechanism_per_transfer.documented == true
	input.gdpr.transfers.inventory.regularly_reviewed == true
}

transfer_log if {
	input.gdpr.transfers.log.maintained == true
	input.gdpr.transfers.log.date.recorded == true
	input.gdpr.transfers.log.recipient.recorded == true
	input.gdpr.transfers.log.data_categories.recorded == true
	input.gdpr.transfers.log.legal_basis.recorded == true
}

data_subjects_informed_of_transfers if {
	input.gdpr.transfers.transparency.privacy_notice.mentions_transfers == true
	input.gdpr.transfers.transparency.countries.identified == true
	input.gdpr.transfers.transparency.safeguards.mentioned == true
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	transfer_principles
	transfer_inventory
	data_subjects_informed_of_transfers

	# Must use at least one valid transfer mechanism
	transfer_mechanism_in_place
}

transfer_mechanism_in_place if {
	adequacy_decision
} else if {
	standard_contractual_clauses
	transfer_impact_assessment
} else if {
	binding_corporate_rules
} else if {
	eu_us_dpf
} else if {
	derogation_if_used
}

report := {
	"standard": "GDPR Chapter V — International Data Transfers",
	"compliant": compliant,
	"transfer_principles": transfer_principles,
	"mechanisms": {
		"adequacy_decision": adequacy_decision,
		"standard_contractual_clauses": standard_contractual_clauses,
		"transfer_impact_assessment": transfer_impact_assessment,
		"supplementary_measures": supplementary_measures,
		"binding_corporate_rules": binding_corporate_rules,
		"eu_us_data_privacy_framework": eu_us_dpf,
		"derogations": derogation_if_used,
	},
	"governance": {
		"transfer_inventory": transfer_inventory,
		"transfer_log": transfer_log,
		"transparency_to_data_subjects": data_subjects_informed_of_transfers,
	},
}
