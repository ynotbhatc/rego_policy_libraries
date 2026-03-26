package hipaa.privacy_rule

import rego.v1

# HIPAA Privacy Rule (45 CFR Part 164, Subparts A and E)
# Governs the use and disclosure of Protected Health Information (PHI)
#
# Complements hipaa_security_rule.rego which covers electronic PHI (ePHI) controls

# =============================================================================
# NOTICE OF PRIVACY PRACTICES (§164.520)
# =============================================================================

notice_of_privacy_practices if {
	input.hipaa.privacy.npp.documented == true
	input.hipaa.privacy.npp.plain_language == true
	input.hipaa.privacy.npp.provided_at_first_service == true
	input.hipaa.privacy.npp.posted_in_facility == true
	input.hipaa.privacy.npp.available_on_website == true
	input.hipaa.privacy.npp.includes_uses_and_disclosures == true
	input.hipaa.privacy.npp.includes_individual_rights == true
	input.hipaa.privacy.npp.includes_complaint_process == true
	input.hipaa.privacy.npp.includes_contact_info == true
	input.hipaa.privacy.npp.reviewed_and_updated_as_needed == true
}

# =============================================================================
# PERMITTED USES AND DISCLOSURES (§164.506-§164.514)
# =============================================================================

# Uses/disclosures for treatment, payment, and operations are documented
tpo_uses_documented if {
	input.hipaa.privacy.tpo.treatment.uses_defined == true
	input.hipaa.privacy.tpo.payment.uses_defined == true
	input.hipaa.privacy.tpo.operations.uses_defined == true
	input.hipaa.privacy.tpo.minimum_necessary.applied == true
}

# Authorization requirements for non-TPO disclosures
authorization_process if {
	input.hipaa.privacy.authorization.required_for_non_tpo == true
	input.hipaa.privacy.authorization.elements.all_required_elements == true
	input.hipaa.privacy.authorization.elements.expiration_date == true
	input.hipaa.privacy.authorization.elements.revocation_right == true
	input.hipaa.privacy.authorization.records.retained_six_years == true
	input.hipaa.privacy.authorization.copies_provided_to_individual == true
}

# Prohibited disclosures
prohibited_disclosures if {
	input.hipaa.privacy.prohibited.sale_of_phi.not_permitted_without_auth == true
	input.hipaa.privacy.prohibited.marketing.not_without_auth == true
	input.hipaa.privacy.prohibited.fundraising.opt_out_provided == true
}

# =============================================================================
# MINIMUM NECESSARY STANDARD (§164.502(b), §164.514(d))
# =============================================================================

minimum_necessary if {
	input.hipaa.privacy.minimum_necessary.policies.documented == true
	input.hipaa.privacy.minimum_necessary.routine_disclosures.limited == true
	input.hipaa.privacy.minimum_necessary.requests.limited_to_needed == true
	input.hipaa.privacy.minimum_necessary.role_based_access.implemented == true
	input.hipaa.privacy.minimum_necessary.workforce_access.limited_to_job_function == true
}

# =============================================================================
# INDIVIDUAL RIGHTS (§164.522-§164.528)
# =============================================================================

# Right of access to PHI (§164.524)
right_of_access if {
	input.hipaa.privacy.rights.access.process_defined == true
	input.hipaa.privacy.rights.access.response_within_30_days == true
	input.hipaa.privacy.rights.access.extension_allowed_30_days == true
	input.hipaa.privacy.rights.access.fee_limited_to_cost == true
	input.hipaa.privacy.rights.access.electronic_format_available == true
	input.hipaa.privacy.rights.access.third_party_directed_allowed == true
	input.hipaa.privacy.rights.access.denials.documented == true
}

# Right to amend PHI (§164.526)
right_to_amend if {
	input.hipaa.privacy.rights.amendment.process_defined == true
	input.hipaa.privacy.rights.amendment.response_within_60_days == true
	input.hipaa.privacy.rights.amendment.denials.basis_documented == true
	input.hipaa.privacy.rights.amendment.accepted.propagated_to_relevant_parties == true
}

# Right to an accounting of disclosures (§164.528)
right_to_accounting if {
	input.hipaa.privacy.rights.accounting.tracking_implemented == true
	input.hipaa.privacy.rights.accounting.six_years_retained == true
	input.hipaa.privacy.rights.accounting.provided_within_60_days == true
	input.hipaa.privacy.rights.accounting.first_request_free == true
	input.hipaa.privacy.rights.accounting.excludes_tpo == true
}

# Right to request restrictions (§164.522)
right_to_restrict if {
	input.hipaa.privacy.rights.restrictions.process_defined == true
	input.hipaa.privacy.rights.restrictions.out_of_pocket_payment.must_honor == true
}

# Right to confidential communications (§164.522(b))
right_to_confidential_comms if {
	input.hipaa.privacy.rights.confidential_communications.process_defined == true
	input.hipaa.privacy.rights.confidential_communications.reasonable_requests_accommodated == true
}

# Right to opt out of directory / fundraising
right_to_opt_out if {
	input.hipaa.privacy.rights.opt_out.facility_directory == true
	input.hipaa.privacy.rights.opt_out.fundraising == true
}

# =============================================================================
# DE-IDENTIFICATION STANDARDS (§164.514)
# =============================================================================

de_identification if {
	# Expert determination method OR safe harbor method
	input.hipaa.privacy.de_identification.method.documented == true

	# Safe harbor: all 18 identifiers removed
	safe_harbor_de_identification
}

safe_harbor_de_identification if {
	input.hipaa.privacy.de_identification.safe_harbor.names.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.geographic.zip_to_3digits_or_less == true
	input.hipaa.privacy.de_identification.safe_harbor.dates.age_over_89_obscured == true
	input.hipaa.privacy.de_identification.safe_harbor.phone_numbers.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.ssn.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.mrn.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.health_plan_numbers.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.account_numbers.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.certificate_numbers.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.device_identifiers.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.urls.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.ip_addresses.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.biometric_identifiers.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.full_face_photos.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.unique_identifiers.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.no_re_identification_knowledge == true
}

# =============================================================================
# WORKFORCE TRAINING AND SANCTIONS (§164.530)
# =============================================================================

workforce_training if {
	input.hipaa.privacy.workforce.training.documented == true
	input.hipaa.privacy.workforce.training.all_staff.completed == true
	input.hipaa.privacy.workforce.training.new_hires.within_30_days == true
	input.hipaa.privacy.workforce.training.frequency.annual == true
	input.hipaa.privacy.workforce.training.role_specific.implemented == true
	input.hipaa.privacy.workforce.training.records.maintained == true
}

sanction_policy if {
	input.hipaa.privacy.sanctions.policy.documented == true
	input.hipaa.privacy.sanctions.applied_to_all_workforce == true
	input.hipaa.privacy.sanctions.violations.investigated == true
	input.hipaa.privacy.sanctions.consistent_application == true
}

# =============================================================================
# PRIVACY OFFICER AND COMPLAINT PROCESS (§164.530)
# =============================================================================

privacy_officer if {
	input.hipaa.privacy.privacy_officer.designated == true
	input.hipaa.privacy.privacy_officer.contact_info.published == true
	input.hipaa.privacy.privacy_officer.responsibilities.documented == true
}

complaint_process if {
	input.hipaa.privacy.complaints.process.documented == true
	input.hipaa.privacy.complaints.contact_info.published == true
	input.hipaa.privacy.complaints.hhs_complaint_right.communicated == true
	input.hipaa.privacy.complaints.log.maintained == true
	input.hipaa.privacy.complaints.investigation.conducted == true
	input.hipaa.privacy.complaints.retaliation.prohibited == true
}

# =============================================================================
# BUSINESS ASSOCIATE AGREEMENTS (§164.504(e))
# =============================================================================

business_associate_agreements if {
	input.hipaa.privacy.baa.required_for_all_bas == true
	input.hipaa.privacy.baa.uses_and_disclosures.limited == true
	input.hipaa.privacy.baa.safeguards.required == true
	input.hipaa.privacy.baa.subcontractors.covered == true
	input.hipaa.privacy.baa.phi_return_or_destruction.required == true
	input.hipaa.privacy.baa.breach_reporting.required == true
	input.hipaa.privacy.baa.inventory.maintained == true
}

# =============================================================================
# DOCUMENTATION AND RECORD RETENTION (§164.530(j))
# =============================================================================

documentation_retention if {
	input.hipaa.privacy.documentation.policies_and_procedures.maintained == true
	input.hipaa.privacy.documentation.retention_years >= 6
	input.hipaa.privacy.documentation.accessible == true
	input.hipaa.privacy.documentation.communications.retained == true
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	notice_of_privacy_practices
	tpo_uses_documented
	authorization_process
	minimum_necessary
	right_of_access
	right_to_amend
	right_to_accounting
	workforce_training
	sanction_policy
	privacy_officer
	complaint_process
	business_associate_agreements
	documentation_retention
}

report := {
	"standard": "HIPAA Privacy Rule (45 CFR Part 164 Subparts A & E)",
	"compliant": compliant,
	"notice_of_privacy_practices": notice_of_privacy_practices,
	"uses_and_disclosures": {
		"tpo_documented": tpo_uses_documented,
		"authorization_process": authorization_process,
		"prohibited_disclosures": prohibited_disclosures,
	},
	"minimum_necessary": minimum_necessary,
	"individual_rights": {
		"access": right_of_access,
		"amendment": right_to_amend,
		"accounting_of_disclosures": right_to_accounting,
		"restrictions": right_to_restrict,
		"confidential_communications": right_to_confidential_comms,
		"opt_out": right_to_opt_out,
	},
	"de_identification": de_identification,
	"workforce": {
		"training": workforce_training,
		"sanctions": sanction_policy,
	},
	"governance": {
		"privacy_officer": privacy_officer,
		"complaint_process": complaint_process,
	},
	"business_associates": business_associate_agreements,
	"documentation_retention": documentation_retention,
}
