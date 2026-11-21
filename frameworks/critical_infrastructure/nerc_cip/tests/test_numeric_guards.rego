package nerc_cip.cip_007_numeric_guards_test

import rego.v1

# "1" sorts above every number in Rego and null below: a non-number lockout threshold must not pass.
test_string_lockout_threshold_not_enforced if {
	not data.nerc_cip.cip_007.password_policy_enforced with input as {"password_policy": {
		"minimum_length": 12,
		"complexity_required": true,
		"expiration_configured": true,
		"account_lockout_configured": true,
		"lockout_threshold": "1",
	}}
}

test_null_lockout_threshold_not_enforced if {
	not data.nerc_cip.cip_007.password_policy_enforced with input as {"password_policy": {
		"minimum_length": 12,
		"complexity_required": true,
		"expiration_configured": true,
		"account_lockout_configured": true,
		"lockout_threshold": null,
	}}
}

test_text_minimum_length_not_enforced if {
	not data.nerc_cip.cip_007.password_policy_enforced with input as {"password_policy": {
		"minimum_length": "x",
		"complexity_required": true,
		"expiration_configured": true,
		"account_lockout_configured": true,
		"lockout_threshold": 5,
	}}
}

test_numeric_password_policy_still_enforced if {
	data.nerc_cip.cip_007.password_policy_enforced with input as {"password_policy": {
		"minimum_length": 12,
		"complexity_required": true,
		"expiration_configured": true,
		"account_lockout_configured": true,
		"lockout_threshold": 5,
	}}
}
