package gdpr.cookies_tracking_numeric_guards_test

import rego.v1

# "1" sorts above every number: a string retention passed `>= 24`.
test_string_consent_records_is_false if {
	not data.gdpr.cookies_tracking.consent_records with input as {"cookies": {"consent": {"records": {"timestamp": {"stored": true}, "user_id_or_session": {"stored": true}, "choices_stored": true, "cmp_version": {"stored": true}, "retention_months": "1"}}}}
}

test_null_consent_records_is_false if {
	not data.gdpr.cookies_tracking.consent_records with input as {"cookies": {"consent": {"records": {"timestamp": {"stored": true}, "user_id_or_session": {"stored": true}, "choices_stored": true, "cmp_version": {"stored": true}, "retention_months": null}}}}
}

test_text_consent_records_is_false if {
	not data.gdpr.cookies_tracking.consent_records with input as {"cookies": {"consent": {"records": {"timestamp": {"stored": true}, "user_id_or_session": {"stored": true}, "choices_stored": true, "cmp_version": {"stored": true}, "retention_months": "x"}}}}
}

test_numeric_consent_records_unchanged if {
	data.gdpr.cookies_tracking.consent_records with input as {"cookies": {"consent": {"records": {"timestamp": {"stored": true}, "user_id_or_session": {"stored": true}, "choices_stored": true, "cmp_version": {"stored": true}, "retention_months": 36}}}}
}
