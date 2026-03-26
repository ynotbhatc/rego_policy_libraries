package gdpr.cookies_tracking

import rego.v1

# GDPR + ePrivacy Directive (2002/58/EC as amended by 2009/136/EC)
# Controls for cookie consent, tracking technologies, and digital marketing
#
# Note: ePrivacy Regulation (pending) will replace the Directive when enacted.
# This policy covers current obligations under ePrivacy Directive + GDPR Art 6.

# =============================================================================
# COOKIE CONSENT (ePrivacy Art. 5(3) + GDPR Art. 7)
# =============================================================================

# Cookie banner / consent mechanism
cookie_consent_mechanism if {
	input.cookies.consent.mechanism.implemented == true
	input.cookies.consent.mechanism.prior_to_placement == true
	input.cookies.consent.mechanism.clearly_displayed == true
	input.cookies.consent.mechanism.cookie_wall.not_used == true  # Pre-ticking / no cookie walls
	input.cookies.consent.mechanism.decline_as_easy_as_accept == true
}

# Consent quality requirements
consent_quality if {
	input.cookies.consent.freely_given == true
	input.cookies.consent.specific == true
	input.cookies.consent.informed == true
	input.cookies.consent.unambiguous_affirmative_act == true
	input.cookies.consent.granular.per_purpose_or_per_cookie == true
	input.cookies.consent.records_maintained == true
	input.cookies.consent.withdrawal.easy == true
	input.cookies.consent.withdrawal.effects_honored == true
}

# Strictly necessary cookies — exempt from consent
strictly_necessary_exempt if {
	input.cookies.strictly_necessary.identified == true
	input.cookies.strictly_necessary.documented == true
	input.cookies.strictly_necessary.only_essential_functionality == true
	input.cookies.strictly_necessary.not_used_for_tracking == true
}

# =============================================================================
# COOKIE CATEGORIES AND CLASSIFICATION
# =============================================================================

cookie_inventory if {
	input.cookies.inventory.maintained == true
	input.cookies.inventory.all_cookies.listed == true
	input.cookies.inventory.categories.classified == true
	input.cookies.inventory.third_party_cookies.identified == true
	input.cookies.inventory.retention_period.documented == true
	input.cookies.inventory.regularly_reviewed == true
}

# Cookie categories properly handled
cookie_categories_compliant if {
	# Necessary: no consent required
	input.cookies.categories.necessary.no_consent_required == true

	# Preferences/functional: consent required
	input.cookies.categories.preferences.consent_required == true

	# Statistics/analytics: consent required (unless anonymised to browser level)
	input.cookies.categories.statistics.consent_required == true

	# Marketing: consent required
	input.cookies.categories.marketing.consent_required == true
}

# =============================================================================
# COOKIE NOTICE / PRIVACY NOTICE
# =============================================================================

cookie_notice if {
	input.cookies.notice.available == true
	input.cookies.notice.plain_language == true
	input.cookies.notice.purpose_of_each_cookie.explained == true
	input.cookies.notice.duration_of_each_cookie.explained == true
	input.cookies.notice.third_parties.identified == true
	input.cookies.notice.how_to_withdraw_consent.explained == true
	input.cookies.notice.link_from_banner == true
}

# =============================================================================
# TRACKING TECHNOLOGIES BEYOND COOKIES
# =============================================================================

# Local storage / session storage
local_storage_compliant if {
	input.cookies.local_storage.classified == true
	input.cookies.local_storage.consent_required_where_non_essential == true
	input.cookies.local_storage.retention.managed == true
}

# Fingerprinting
fingerprinting_controlled if {
	not input.cookies.fingerprinting.used
} else if {
	input.cookies.fingerprinting.used
	input.cookies.fingerprinting.consent.obtained == true
	input.cookies.fingerprinting.purpose.documented == true
	input.cookies.fingerprinting.privacy_notice.disclosed == true
}

# Tracking pixels / web beacons
tracking_pixels_compliant if {
	not input.cookies.tracking_pixels.used
} else if {
	input.cookies.tracking_pixels.used
	input.cookies.tracking_pixels.consent.obtained == true
	input.cookies.tracking_pixels.third_parties.disclosed == true
}

# =============================================================================
# CONSENT MANAGEMENT PLATFORM (CMP)
# =============================================================================

cmp_implementation if {
	input.cookies.cmp.implemented == true
	input.cookies.cmp.iab_tcf_or_equivalent.compliant == true
	input.cookies.cmp.consent_string.stored_and_passed == true
	input.cookies.cmp.vendor_list.current == true
	input.cookies.cmp.consent_expiry.configured == true
	input.cookies.cmp.re_consent.triggered_on_material_change == true
}

# Consent record keeping
consent_records if {
	input.cookies.consent.records.timestamp.stored == true
	input.cookies.consent.records.user_id_or_session.stored == true
	input.cookies.consent.records.choices_stored == true
	input.cookies.consent.records.cmp_version.stored == true
	input.cookies.consent.records.retention_months >= 24
}

# =============================================================================
# DIRECT MARKETING AND PROFILING
# =============================================================================

# Email marketing consent
email_marketing_consent if {
	input.marketing.email.opt_in.required == true
	input.marketing.email.double_opt_in.implemented == true
	input.marketing.email.unsubscribe.in_every_email == true
	input.marketing.email.unsubscribe.honored_within_10_days == true
	input.marketing.email.existing_customers.soft_opt_in_if_similar_products == true
	input.marketing.email.records.maintained == true
}

# Profiling and automated decision-making (GDPR Art. 22)
automated_decision_making if {
	not input.profiling.solely_automated_with_legal_effect.used
} else if {
	input.profiling.solely_automated_with_legal_effect.used
	input.profiling.lawful_basis.one_of_three_bases == true
	input.profiling.data_subjects.informed == true
	input.profiling.data_subjects.right_to_human_review == true
	input.profiling.data_subjects.right_to_contest == true
	input.profiling.special_category_data.not_used_without_explicit_consent == true
}

# Behavioural advertising
behavioural_advertising if {
	not input.marketing.behavioural_advertising.used
} else if {
	input.marketing.behavioural_advertising.used
	input.marketing.behavioural_advertising.consent.obtained == true
	input.marketing.behavioural_advertising.profiling.disclosed == true
	input.marketing.behavioural_advertising.opt_out.easy == true
	input.marketing.behavioural_advertising.sensitive_categories.not_targeted == true
}

# =============================================================================
# CHILDREN'S DATA (GDPR Art. 8 + COPPA equivalent considerations)
# =============================================================================

childrens_data if {
	not input.gdpr.childrens_data.services_directed_at_children
} else if {
	input.gdpr.childrens_data.services_directed_at_children
	input.gdpr.childrens_data.age_verification.implemented == true
	input.gdpr.childrens_data.parental_consent.required_under_16 == true
	input.gdpr.childrens_data.parental_consent.verification == true
	input.gdpr.childrens_data.privacy_notice.child_friendly == true
	input.gdpr.childrens_data.behavioural_advertising.not_to_children == true
	input.gdpr.childrens_data.profiling.not_to_children == true
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	cookie_consent_mechanism
	consent_quality
	strictly_necessary_exempt
	cookie_inventory
	cookie_categories_compliant
	cookie_notice
	cmp_implementation
	consent_records
	email_marketing_consent
}

report := {
	"standard": "GDPR Art. 6/7 + ePrivacy Directive — Cookies and Tracking",
	"compliant": compliant,
	"cookie_consent": {
		"mechanism": cookie_consent_mechanism,
		"quality": consent_quality,
		"strictly_necessary_exempt": strictly_necessary_exempt,
	},
	"cookie_governance": {
		"inventory": cookie_inventory,
		"categories": cookie_categories_compliant,
		"notice": cookie_notice,
	},
	"tracking_technologies": {
		"local_storage": local_storage_compliant,
		"fingerprinting": fingerprinting_controlled,
		"tracking_pixels": tracking_pixels_compliant,
	},
	"consent_management": {
		"cmp_implementation": cmp_implementation,
		"consent_records": consent_records,
	},
	"marketing_and_profiling": {
		"email_marketing": email_marketing_consent,
		"automated_decisions": automated_decision_making,
		"behavioural_advertising": behavioural_advertising,
	},
	"childrens_data": childrens_data,
}
