# Unit tests for gdpr.compliance (frameworks/privacy/gdpr/gdpr_compliance.rego)
# Closes GitHub issue #80.
#
# This module exposes boolean predicate rules (not `violation contains msg`
# sets) plus a `report` object. Each predicate is exercised with an input that
# makes it fire (assert true), the multi-branch predicates are exercised on both
# branches, a couple of negative cases assert fail-closed behaviour, and the
# `report` entrypoint is asserted to be a populated object on empty input.
package gdpr.compliance_test

import rego.v1

import data.gdpr.compliance as pkg

# A fully compliant fixture — satisfies every predicate in the module.
full_input := {"gdpr": {
	"lawful_basis": {
		"documented": true,
		"recorded_per_processing_activity": true,
		"reviewed_regularly": true,
	},
	"consent": {
		"freely_given": true,
		"specific": true,
		"informed": true,
		"unambiguous": true,
		"records_maintained": true,
		"withdrawal_as_easy_as_giving": true,
		"pre_ticked_boxes": {"not_used": true},
	},
	"special_category_data": {
		"processed": true,
		"explicit_consent": true,
		"legal_basis": {"documented": true},
		"dpia": {"conducted": true},
		"additional_safeguards": {"implemented": true},
	},
	"data_subject_rights": {
		"access": {
			"process_defined": true,
			"response_within_30_days": true,
			"identity_verification": true,
			"free_of_charge": true,
		},
		"rectification": {
			"process_defined": true,
			"third_parties_notified": true,
		},
		"erasure": {
			"process_defined": true,
			"secure_deletion_implemented": true,
			"third_parties_notified": true,
			"backups_addressed": true,
		},
		"portability": {
			"structured_format_available": true,
			"machine_readable": true,
			"common_format_used": true,
		},
		"objection": {
			"process_defined": true,
			"direct_marketing": {"always_honoured": true},
		},
	},
	"privacy_by_design": {
		"principles": {
			"data_minimisation": true,
			"purpose_limitation": true,
			"storage_limitation": true,
		},
		"implemented_at_design_phase": true,
		"default_settings": {"privacy_protective": true},
		"sdlc_integrated": true,
	},
	"dpia": {
		"policy": {"documented": true},
		"high_risk_processing": {"triggers_dpia": true},
		"new_technologies": {"triggers_dpia": true},
		"large_scale_monitoring": {"triggers_dpia": true},
		"dpo": {"consulted": true},
		"results": {"documented": true},
	},
	"dpo": {
		"mandatory": true,
		"appointed": true,
		"contact_details": {
			"published": true,
			"notified_to_supervisory_authority": true,
		},
		"independence": {"guaranteed": true},
		"resources": {"adequate": true},
	},
	"records_of_processing": {
		"maintained": true,
		"controller_record": {"complete": true},
		"includes": {
			"purposes": true,
			"data_categories": true,
			"recipients": true,
			"retention_periods": true,
			"security_measures": true,
		},
		"regularly_reviewed": true,
	},
	"breach_notification": {
		"policy": {"documented": true},
		"detection": {"controls_in_place": true},
		"supervisory_authority": {"within_72_hours": true},
		"risk_assessment": {"performed": true},
		"data_subjects": {"notified_when_high_risk": true},
		"register": {"maintained": true},
	},
	"international_transfers": {
		"occur": true,
		"adequacy_decision_or_safeguards": true,
		"mechanism": {"documented": true},
		"scc_or_bcr": {"implemented": true},
		"data_subjects": {"informed": true},
	},
	"technical_measures": {
		"encryption": {
			"personal_data_at_rest": true,
			"personal_data_in_transit": true,
		},
		"pseudonymisation": {"implemented": true},
		"anonymisation": {"process_defined": true},
		"confidentiality": {"access_controls": true},
		"integrity": {"checksums_or_signatures": true},
		"availability": {"backup_and_recovery": true},
		"resilience": {"systems_resilient": true},
		"restore": {"timely_restoration_capability": true},
		"testing": {
			"regular_security_testing": true,
			"effectiveness_evaluated": true,
		},
	},
	"retention": {
		"policy": {"documented": true},
		"periods": {"defined_per_category": true},
		"automated_deletion": {"implemented": true},
		"review": {"regular": true},
		"legal_hold": {"process_defined": true},
	},
	"data_minimisation": {
		"collection_limited_to_purpose": true,
		"fields_reviewed_regularly": true,
		"unnecessary_data": {"not_collected": true},
	},
	"processors": {
		"contracts": {
			"required": true,
			"article_28_compliant": true,
			"processing_instructions_documented": true,
			"sub_processor_approval": {"required": true},
		},
		"inventory": {"maintained": true},
		"due_diligence": {"performed": true},
	},
}}

# ---------------------------------------------------------------------------
# Lawfulness of processing (Articles 6, 7, 9)
# ---------------------------------------------------------------------------

test_lawful_basis_established_fires if {
	pkg.lawful_basis_established with input as full_input
}

test_lawful_basis_not_established_on_empty if {
	not pkg.lawful_basis_established with input as {}
}

test_consent_management_fires if {
	pkg.consent_management with input as full_input
}

# else-branch: special category data processed with all safeguards.
test_special_category_data_processed_with_safeguards if {
	pkg.special_category_data with input as full_input
}

# first branch: special category data not processed at all.
test_special_category_data_not_processed if {
	pkg.special_category_data with input as {"gdpr": {"special_category_data": {"processed": false}}}
}

# processed but missing a safeguard -> fails.
test_special_category_data_missing_safeguard_fails if {
	not pkg.special_category_data with input as {"gdpr": {"special_category_data": {
		"processed": true,
		"explicit_consent": true,
		"legal_basis": {"documented": true},
		"dpia": {"conducted": true},
		"additional_safeguards": {"implemented": false},
	}}}
}

# ---------------------------------------------------------------------------
# Data subject rights (Articles 12-23)
# ---------------------------------------------------------------------------

test_right_of_access_fires if {
	pkg.right_of_access with input as full_input
}

test_right_to_rectification_fires if {
	pkg.right_to_rectification with input as full_input
}

test_right_to_erasure_fires if {
	pkg.right_to_erasure with input as full_input
}

test_right_to_portability_fires if {
	pkg.right_to_portability with input as full_input
}

test_right_to_object_fires if {
	pkg.right_to_object with input as full_input
}

# ---------------------------------------------------------------------------
# Accountability (Articles 25, 35, 37-39, 30)
# ---------------------------------------------------------------------------

test_privacy_by_design_fires if {
	pkg.privacy_by_design with input as full_input
}

test_dpia_process_fires if {
	pkg.dpia_process with input as full_input
}

# else-branch: DPO mandatory and fully satisfied.
test_dpo_requirements_mandatory_satisfied if {
	pkg.dpo_requirements with input as full_input
}

# first branch: DPO not mandatory.
test_dpo_requirements_not_mandatory if {
	pkg.dpo_requirements with input as {"gdpr": {"dpo": {"mandatory": false}}}
}

# mandatory but not appointed -> fails.
test_dpo_requirements_mandatory_unappointed_fails if {
	not pkg.dpo_requirements with input as {"gdpr": {"dpo": {
		"mandatory": true,
		"appointed": false,
	}}}
}

test_records_of_processing_fires if {
	pkg.records_of_processing with input as full_input
}

# ---------------------------------------------------------------------------
# Incident management (Articles 33-34)
# ---------------------------------------------------------------------------

test_breach_notification_fires if {
	pkg.breach_notification with input as full_input
}

# ---------------------------------------------------------------------------
# International transfers (Articles 44-49)
# ---------------------------------------------------------------------------

# else-branch: transfers occur with adequacy/safeguards.
test_international_transfers_occur_with_safeguards if {
	pkg.international_transfers with input as full_input
}

# first branch: no international transfers occur.
test_international_transfers_none_occur if {
	pkg.international_transfers with input as {"gdpr": {"international_transfers": {"occur": false}}}
}

# occur but no safeguards -> fails.
test_international_transfers_no_safeguards_fails if {
	not pkg.international_transfers with input as {"gdpr": {"international_transfers": {
		"occur": true,
		"adequacy_decision_or_safeguards": false,
	}}}
}

# ---------------------------------------------------------------------------
# Technical security measures (Article 32)
# ---------------------------------------------------------------------------

test_encryption_pseudonymisation_fires if {
	pkg.encryption_pseudonymisation with input as full_input
}

test_ongoing_confidentiality_integrity_fires if {
	pkg.ongoing_confidentiality_integrity with input as full_input
}

test_restore_and_test_fires if {
	pkg.restore_and_test with input as full_input
}

# ---------------------------------------------------------------------------
# Data governance (Articles 5, 17, 28)
# ---------------------------------------------------------------------------

test_data_retention_fires if {
	pkg.data_retention with input as full_input
}

test_data_minimisation_fires if {
	pkg.data_minimisation with input as full_input
}

test_processor_agreements_fires if {
	pkg.processor_agreements with input as full_input
}

# ---------------------------------------------------------------------------
# Overall compliance + report entrypoint
# ---------------------------------------------------------------------------

test_compliant_true_on_full_input if {
	pkg.compliant with input as full_input
}

test_not_compliant_on_empty_input if {
	not pkg.compliant with input as {}
}

# Report entrypoint must be a populated object on empty input (never the
# undefined -> {} collapse).
test_report_wellformed_on_empty_input if {
	report := pkg.report with input as {}
	is_object(report)
	count(report) > 0
}

# On the full fixture the report is populated and reports overall compliance.
test_report_compliant_on_full_input if {
	report := pkg.report with input as full_input
	is_object(report)
	count(report) > 0
	report.compliant == true
}
