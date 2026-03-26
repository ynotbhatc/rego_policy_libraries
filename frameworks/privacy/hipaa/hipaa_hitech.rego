package hipaa.hitech

import rego.v1

# HITECH Act (Health Information Technology for Economic and Clinical Health Act)
# Enacted as part of ARRA 2009 — strengthens HIPAA with stricter breach notification,
# expanded BA liability, increased penalties, and EHR incentive requirements
#
# Key provisions: 42 U.S.C. §§ 17921-17954

# =============================================================================
# BREACH NOTIFICATION RULE (42 U.S.C. §17932 / 45 CFR §§164.400-414)
# =============================================================================

# Four-factor risk assessment to determine if breach must be reported
breach_risk_assessment if {
	input.hitech.breach_assessment.nature_and_extent.evaluated == true
	input.hitech.breach_assessment.who_accessed_phi.evaluated == true
	input.hitech.breach_assessment.whether_phi_acquired.evaluated == true
	input.hitech.breach_assessment.mitigation_extent.evaluated == true
	input.hitech.breach_assessment.documented == true
	input.hitech.breach_assessment.result.low_probability_exception.documented_when_applied == true
}

# Individual notification requirements
individual_breach_notification if {
	input.hitech.breach_notification.individuals.within_60_days == true
	input.hitech.breach_notification.individuals.written_notice == true
	input.hitech.breach_notification.individuals.includes_description == true
	input.hitech.breach_notification.individuals.includes_types_of_phi == true
	input.hitech.breach_notification.individuals.includes_steps_to_protect == true
	input.hitech.breach_notification.individuals.includes_investigation_steps == true
	input.hitech.breach_notification.individuals.includes_contact_info == true
}

# HHS notification requirements
hhs_breach_notification if {
	input.hitech.breach_notification.hhs.small_breaches.annual_log.submitted == true
	input.hitech.breach_notification.hhs.large_breaches.within_60_days == true
	input.hitech.breach_notification.hhs.large_breaches_500_plus.media_notice == true
}

# Media notification for large breaches
media_breach_notification if {
	input.hitech.breach_notification.media.required_threshold_500 == true
	input.hitech.breach_notification.media.state_or_jurisdiction.prominent_media_outlets == true
	input.hitech.breach_notification.media.within_60_days == true
}

# Breach log maintenance
breach_log_maintained if {
	input.hitech.breach_log.maintained == true
	input.hitech.breach_log.all_breaches.documented == true
	input.hitech.breach_log.sub_500_breaches.included == true
	input.hitech.breach_log.retention_years >= 6
}

# =============================================================================
# EXPANDED BUSINESS ASSOCIATE LIABILITY (42 U.S.C. §17934)
# =============================================================================

# BAs directly liable under HIPAA Security and Privacy Rules
ba_direct_liability if {
	input.hitech.business_associates.directly_liable == true
	input.hitech.business_associates.security_rule.applies_directly == true
	input.hitech.business_associates.privacy_rule.applies_to_use_disclosure == true
	input.hitech.business_associates.subcontractors.baa_required == true
}

# Business associate agreements updated for HITECH
baa_hitech_compliant if {
	input.hitech.baa.hitech_provisions.included == true
	input.hitech.baa.breach_notification.ba_notifies_ce_without_unreasonable_delay == true
	input.hitech.baa.breach_notification.within_60_days_max == true
	input.hitech.baa.individual_rights.access_honored == true
	input.hitech.baa.electronic_access.provided_when_requested == true
}

# =============================================================================
# ENFORCEMENT AND PENALTIES (42 U.S.C. §17939 / 45 CFR §160.400+)
# =============================================================================

# Tiered penalty awareness
penalty_awareness if {
	input.hitech.penalties.tier_1.unknown_violation.awareness == true
	input.hitech.penalties.tier_2.reasonable_cause.awareness == true
	input.hitech.penalties.tier_3.willful_neglect_corrected.awareness == true
	input.hitech.penalties.tier_4.willful_neglect_uncorrected.awareness == true
}

# Corrective action plan (CAP) readiness if investigated
cap_readiness if {
	input.hitech.enforcement.cap_template.available == true
	input.hitech.enforcement.compliance_monitoring.internal == true
	input.hitech.enforcement.audit_response.procedures_defined == true
	input.hitech.enforcement.hhs_ocr_cooperation.policy == true
}

# =============================================================================
# PATIENT ACCESS RIGHTS STRENGTHENED BY HITECH (42 U.S.C. §17935)
# =============================================================================

# Covered entities must provide electronic access to ePHI
electronic_access_to_ephi if {
	input.hitech.patient_access.electronic_format.available == true
	input.hitech.patient_access.ehr.access_provided == true
	input.hitech.patient_access.third_party_directed.honored == true
	input.hitech.patient_access.fee.reasonable_cost_based == true
	input.hitech.patient_access.response_time.within_30_days == true
}

# Restriction on disclosure to health plan when patient pays out of pocket
out_of_pocket_restriction if {
	input.hitech.patient_rights.out_of_pocket.restriction_honored == true
	input.hitech.patient_rights.out_of_pocket.health_plan_disclosure.prohibited_when_restricted == true
}

# =============================================================================
# ACCOUNTING OF DISCLOSURES — EHR EXPANSION (42 U.S.C. §17935(c))
# =============================================================================

accounting_ehr_expansion if {
	input.hitech.accounting.ehr.tpo_disclosures.tracked == true
	input.hitech.accounting.ehr.three_year_lookback == true
	input.hitech.accounting.ehr.electronic_format_available == true
}

# =============================================================================
# MINIMUM NECESSARY — HITECH STRENGTHENING
# =============================================================================

hitech_minimum_necessary if {
	input.hitech.minimum_necessary.limited_data_set.preferred == true
	input.hitech.minimum_necessary.de_identified_data.preferred == true
	input.hitech.minimum_necessary.workforce_access.role_based == true
}

# =============================================================================
# EHR SECURITY (HITECH EHR INCENTIVE PROVISIONS)
# =============================================================================

ehr_security_controls if {
	input.hitech.ehr.access_controls.unique_user_id == true
	input.hitech.ehr.access_controls.emergency_access.procedure == true
	input.hitech.ehr.access_controls.automatic_logoff.configured == true
	input.hitech.ehr.encryption.at_rest == true
	input.hitech.ehr.encryption.in_transit == true
	input.hitech.ehr.audit_log.enabled == true
	input.hitech.ehr.audit_log.tamper_evident == true
	input.hitech.ehr.integrity.data_authentication == true
}

# =============================================================================
# HITECH SECURITY CONTROLS — MEANINGFUL USE
# =============================================================================

meaningful_use_security if {
	input.hitech.meaningful_use.security_risk_analysis.conducted == true
	input.hitech.meaningful_use.security_risk_analysis.annually == true
	input.hitech.meaningful_use.security_updates.implemented == true
	input.hitech.meaningful_use.security_deficiencies.corrected == true
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	breach_risk_assessment
	individual_breach_notification
	hhs_breach_notification
	breach_log_maintained
	ba_direct_liability
	baa_hitech_compliant
	cap_readiness
	electronic_access_to_ephi
	out_of_pocket_restriction
	ehr_security_controls
	meaningful_use_security
}

report := {
	"standard": "HITECH Act (42 U.S.C. §§17921-17954)",
	"compliant": compliant,
	"breach_notification": {
		"risk_assessment": breach_risk_assessment,
		"individual_notification": individual_breach_notification,
		"hhs_notification": hhs_breach_notification,
		"media_notification": media_breach_notification,
		"breach_log": breach_log_maintained,
	},
	"business_associate_provisions": {
		"direct_liability": ba_direct_liability,
		"hitech_compliant_baa": baa_hitech_compliant,
	},
	"enforcement": {
		"penalty_awareness": penalty_awareness,
		"cap_readiness": cap_readiness,
	},
	"patient_rights": {
		"electronic_access": electronic_access_to_ephi,
		"out_of_pocket_restriction": out_of_pocket_restriction,
		"accounting_ehr_expansion": accounting_ehr_expansion,
	},
	"ehr_security": {
		"controls": ehr_security_controls,
		"meaningful_use": meaningful_use_security,
	},
	"minimum_necessary": hitech_minimum_necessary,
}
