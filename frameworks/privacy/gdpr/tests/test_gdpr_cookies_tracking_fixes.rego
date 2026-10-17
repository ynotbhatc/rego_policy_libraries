package gdpr.cookies_tracking_test

import rego.v1

test_local_storage_failure_blocks_compliance if {
	not data.gdpr.cookies_tracking.compliant with input as {}
		with data.gdpr.cookies_tracking.cookie_consent_mechanism as true
		with data.gdpr.cookies_tracking.consent_quality as true
		with data.gdpr.cookies_tracking.strictly_necessary_exempt as true
		with data.gdpr.cookies_tracking.cookie_inventory as true
		with data.gdpr.cookies_tracking.cookie_categories_compliant as true
		with data.gdpr.cookies_tracking.cookie_notice as true
		with data.gdpr.cookies_tracking.cmp_implementation as true
		with data.gdpr.cookies_tracking.consent_records as true
		with data.gdpr.cookies_tracking.email_marketing_consent as true
}

test_all_listed_controls_true_is_compliant if {
	data.gdpr.cookies_tracking.compliant with input as {}
		with data.gdpr.cookies_tracking.cookie_consent_mechanism as true
		with data.gdpr.cookies_tracking.consent_quality as true
		with data.gdpr.cookies_tracking.strictly_necessary_exempt as true
		with data.gdpr.cookies_tracking.cookie_inventory as true
		with data.gdpr.cookies_tracking.cookie_categories_compliant as true
		with data.gdpr.cookies_tracking.cookie_notice as true
		with data.gdpr.cookies_tracking.cmp_implementation as true
		with data.gdpr.cookies_tracking.consent_records as true
		with data.gdpr.cookies_tracking.email_marketing_consent as true
		with data.gdpr.cookies_tracking.local_storage_compliant as true
}

test_absent_use_flags_do_not_pass_on_empty_input if {
	not data.gdpr.cookies_tracking.fingerprinting_controlled with input as {}
	not data.gdpr.cookies_tracking.tracking_pixels_compliant with input as {}
	not data.gdpr.cookies_tracking.automated_decision_making with input as {}
	not data.gdpr.cookies_tracking.behavioural_advertising with input as {}
	not data.gdpr.cookies_tracking.childrens_data with input as {}
}

test_explicit_not_used_passes if {
	data.gdpr.cookies_tracking.fingerprinting_controlled with input as {"cookies": {"fingerprinting": {"used": false}}}
	data.gdpr.cookies_tracking.tracking_pixels_compliant with input as {"cookies": {"tracking_pixels": {"used": false}}}
	data.gdpr.cookies_tracking.automated_decision_making with input as {"profiling": {"solely_automated_with_legal_effect": {"used": false}}}
	data.gdpr.cookies_tracking.behavioural_advertising with input as {"marketing": {"behavioural_advertising": {"used": false}}}
	data.gdpr.cookies_tracking.childrens_data with input as {"gdpr": {"childrens_data": {"services_directed_at_children": false}}}
}

test_used_without_consent_fails if {
	not data.gdpr.cookies_tracking.fingerprinting_controlled with input as {"cookies": {"fingerprinting": {"used": true}}}
}
